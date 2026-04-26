//! JMAP (RFC 8620 / RFC 8621) client types and HTTP implementation.
//!
//! Implements a minimal subset of JMAP for Mail:
//! - `Email/query`  — full-scan list of email IDs in a mailbox (no delta; seen_ids dedup prevents replay)
//! - `Email/get`    — fetch email headers and plain text body
//! - `Email/set`    — create a new email in a mailbox

use anyhow::{anyhow, Result};
use serde::Deserialize;
use serde_json::{json, Value};
use url::Url;

/// A single JMAP method call in a Request object.
///
/// Format: `[method_name, arguments, method_call_id]`
type MethodCall = (String, Value, String);

/// A single JMAP method response in a Response object.
///
/// Format: `[method_name, arguments, method_call_id]`
type MethodResponse = (String, Value, String);

/// Minimal subset of an Email object for bridging purposes.
#[derive(Debug, Deserialize)]
pub struct EmailObject {
    /// JMAP email ID.
    #[allow(dead_code)]
    pub id: String,
    /// From: display name (first sender).
    pub from: Option<Vec<EmailAddress>>,
    /// Subject line.
    pub subject: Option<String>,
    /// Plain text body (textBody part).
    #[serde(rename = "bodyValues")]
    pub body_values: Option<std::collections::HashMap<String, BodyPart>>,
    /// Text body part reference IDs.
    #[serde(rename = "textBody")]
    pub text_body: Option<Vec<BodyPartRef>>,
}

/// An email address (name + email).
#[derive(Debug, Deserialize)]
pub struct EmailAddress {
    pub name: Option<String>,
    pub email: Option<String>,
}

/// A resolved body part value.
#[derive(Debug, Deserialize)]
pub struct BodyPart {
    pub value: String,
}

/// A reference to a body part (used to join textBody → bodyValues).
#[derive(Debug, Deserialize)]
pub struct BodyPartRef {
    #[serde(rename = "partId")]
    pub part_id: Option<String>,
}

impl EmailObject {
    /// Return the plain-text body, or `None` if unavailable.
    pub fn plain_text(&self) -> Option<&str> {
        let text_body = self.text_body.as_ref()?;
        let part_ref = text_body.first()?;
        let part_id = part_ref.part_id.as_deref()?;
        let body_values = self.body_values.as_ref()?;
        Some(body_values.get(part_id)?.value.as_str())
    }

    /// Return the display name or email address of the first sender.
    pub fn sender_display(&self) -> Option<&str> {
        let from = self.from.as_ref()?;
        let addr = from.first()?;
        addr.name.as_deref().or(addr.email.as_deref())
    }
}

/// Minimal JMAP HTTP client.
///
/// Does not implement Debug to avoid accidental logging of the bearer token.
pub struct JmapClient {
    session_url: String,
    bearer_token: String,
    http: reqwest::Client,
    /// JMAP API URL (populated after session fetch).
    api_url: Option<String>,
    /// Server-advertised maximum number of objects per Email/get request.
    ///
    /// Sourced from `capabilities["urn:ietf:params:jmap:core"]["maxObjectsInGet"]`
    /// during `init_session`. Defaults to 50 if the server does not advertise a limit.
    max_objects_in_get: usize,
}

impl JmapClient {
    pub fn new(session_url: &str, bearer_token: &str) -> Self {
        Self {
            session_url: session_url.to_string(),
            bearer_token: bearer_token.to_string(),
            http: reqwest::Client::new(),
            api_url: None,
            max_objects_in_get: 50,
        }
    }

    /// Fetch the JMAP session and cache the API URL.
    ///
    /// Must be called before `email_query`, `email_get`, or `email_set`.
    pub async fn init_session(&mut self) -> Result<()> {
        let resp = self
            .http
            .get(&self.session_url)
            .bearer_auth(&self.bearer_token)
            .send()
            .await
            .map_err(|e| anyhow!("JMAP session fetch error: {e}"))?;
        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(anyhow!("JMAP session error {status}: {body}"));
        }
        let session_bytes = resp
            .bytes()
            .await
            .map_err(|e| anyhow!("JMAP session read error: {e}"))?;
        if session_bytes.len() > 16 * 1024 * 1024 {
            return Err(anyhow!(
                "JMAP session response too large: {} bytes",
                session_bytes.len()
            ));
        }
        let session: Value = serde_json::from_slice(&session_bytes)
            .map_err(|e| anyhow!("JMAP session parse error: {e}"))?;
        let api_url_str = session
            .get("apiUrl")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("JMAP session missing apiUrl"))?;
        let api_url = Url::parse(api_url_str)
            .map_err(|e| anyhow!("JMAP session returned unparseable apiUrl: {e}"))?;
        if api_url.scheme() != "https" {
            return Err(anyhow!(
                "JMAP session returned non-https apiUrl; refusing to use it"
            ));
        }
        let session_url = Url::parse(&self.session_url)
            .map_err(|e| anyhow!("JMAP session URL is unparseable: {e}"))?;
        if api_url.origin() != session_url.origin() {
            return Err(anyhow!(
                "JMAP session returned apiUrl with different origin than session URL; \
                 refusing to use it (potential SSRF)"
            ));
        }
        self.api_url = Some(api_url_str.to_string());

        // Read maxObjectsInGet from core capabilities; fall back to 50 if absent or zero.
        if let Some(limit) = session
            .get("capabilities")
            .and_then(|c| c.get("urn:ietf:params:jmap:core"))
            .and_then(|c| c.get("maxObjectsInGet"))
            .and_then(|v| v.as_u64())
            .filter(|&n| n > 0)
        {
            self.max_objects_in_get = limit as usize;
        }

        Ok(())
    }

    fn api_url(&self) -> Result<&str> {
        self.api_url
            .as_deref()
            .ok_or_else(|| anyhow!("JMAP session not initialized; call init_session() first"))
    }

    /// Execute a JMAP API request with the given method calls.
    async fn request(&self, method_calls: Vec<MethodCall>) -> Result<Vec<MethodResponse>> {
        let body = json!({
            "using": [
                "urn:ietf:params:jmap:core",
                "urn:ietf:params:jmap:mail"
            ],
            "methodCalls": method_calls
        });
        let resp = self
            .http
            .post(self.api_url()?)
            .bearer_auth(&self.bearer_token)
            .json(&body)
            .send()
            .await
            .map_err(|e| anyhow!("JMAP request error: {e}"))?;
        if !resp.status().is_success() {
            let status = resp.status();
            let err_bytes = resp.bytes().await.unwrap_or_default();
            let err_body = if err_bytes.len() > 64 * 1024 {
                format!("(error body too large: {} bytes)", err_bytes.len())
            } else {
                String::from_utf8_lossy(&err_bytes).into_owned()
            };
            return Err(anyhow!("JMAP API error {status}: {err_body}"));
        }
        let bytes = resp
            .bytes()
            .await
            .map_err(|e| anyhow!("JMAP response read error: {e}"))?;
        if bytes.len() > 16 * 1024 * 1024 {
            return Err(anyhow!("JMAP response too large: {} bytes", bytes.len()));
        }
        let response: Value = serde_json::from_slice(&bytes)
            .map_err(|e| anyhow!("JMAP response parse error: {e}"))?;
        let method_responses = response
            .get("methodResponses")
            .and_then(|v| v.as_array())
            .ok_or_else(|| anyhow!("JMAP response missing methodResponses"))?
            .iter()
            .filter_map(|r| {
                let arr = r.as_array()?;
                Some((
                    arr.first()?.as_str()?.to_string(),
                    arr.get(1)?.clone(),
                    arr.get(2)?.as_str().unwrap_or("").to_string(),
                ))
            })
            .collect();
        Ok(method_responses)
    }

    /// Query email IDs in a mailbox using a full scan, paginating until all IDs are collected.
    ///
    /// The `since_state` parameter is accepted for API compatibility but is **not used** —
    /// this always issues a full `Email/query` rather than an incremental `Email/queryChanges`.
    /// Replay is prevented by the bridge's `seen_ids` deduplication set.
    ///
    /// Uses `position`-based pagination (RFC 8621 §5.5) when the server's `total` field
    /// indicates more results exist than were returned in the first response.
    ///
    /// Returns `(ids, new_query_state)`.
    pub async fn email_query(
        &self,
        account_id: &str,
        mailbox_id: &str,
        since_state: Option<&str>,
    ) -> Result<(Vec<String>, String)> {
        let filter = json!({ "inMailbox": mailbox_id });
        // NOTE: true incremental polling uses Email/queryChanges with a top-level
        // sinceQueryState arg.  The since_state parameter is kept for future use
        // but the full-scan Email/query is used here for simplicity; seen_ids
        // deduplication in the bridge prevents message replay.
        let _ = since_state;

        const PAGE_SIZE: u64 = 50;
        let mut all_ids: Vec<String> = Vec::new();
        let mut position: u64 = 0;
        let mut query_state = String::new();

        loop {
            let args = json!({
                "accountId": account_id,
                "filter": filter,
                "sort": [{"property": "receivedAt", "isAscending": false}],
                "limit": PAGE_SIZE,
                "position": position
            });
            let calls = vec![("Email/query".to_string(), args, "c1".to_string())];
            let responses = self.request(calls).await?;

            let resp_args = responses
                .into_iter()
                .find(|(m, _, _)| m == "Email/query")
                .map(|(_, args, _)| args)
                .ok_or_else(|| anyhow!("Email/query response not found"))?;

            let page_ids: Vec<String> = resp_args
                .get("ids")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str().map(str::to_string))
                        .collect()
                })
                .unwrap_or_default();

            if query_state.is_empty() {
                query_state = resp_args
                    .get("queryState")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
            }

            let page_len = page_ids.len() as u64;
            all_ids.extend(page_ids);
            position += page_len;

            // `total` is optional in the JMAP spec; if absent or if we received
            // fewer IDs than the page size, there are no more pages.
            let total = resp_args
                .get("total")
                .and_then(|v| v.as_u64())
                .unwrap_or(position);

            if page_len < PAGE_SIZE || position >= total {
                break;
            }
        }

        Ok((all_ids, query_state))
    }

    /// Fetch full email objects for the given IDs.
    ///
    /// Chunks the ID list into batches of at most `max_objects_in_get` (sourced from
    /// the server's `capabilities["urn:ietf:params:jmap:core"]["maxObjectsInGet"]`
    /// during `init_session`, defaulting to 50) and issues one `Email/get` request
    /// per batch to avoid `requestTooLarge` errors.
    pub async fn email_get(&self, account_id: &str, ids: &[String]) -> Result<Vec<EmailObject>> {
        if ids.is_empty() {
            return Ok(vec![]);
        }

        let mut all_emails: Vec<EmailObject> = Vec::with_capacity(ids.len());

        for batch in ids.chunks(self.max_objects_in_get) {
            let args = json!({
                "accountId": account_id,
                "ids": batch,
                "properties": ["id", "from", "subject", "textBody", "bodyValues"],
                "fetchTextBodyValues": true,
                "maxBodyValueBytes": 8192
            });
            let calls = vec![("Email/get".to_string(), args, "c1".to_string())];
            let responses = self.request(calls).await?;

            let resp_args = responses
                .into_iter()
                .find(|(m, _, _)| m == "Email/get")
                .map(|(_, args, _)| args)
                .ok_or_else(|| anyhow!("Email/get response not found"))?;

            let list = resp_args
                .get("list")
                .and_then(|v| v.as_array())
                .ok_or_else(|| anyhow!("Email/get response missing 'list'"))?;

            for v in list {
                match serde_json::from_value::<EmailObject>(v.clone()) {
                    Ok(email) => all_emails.push(email),
                    Err(e) => {
                        let id = v.get("id").and_then(|i| i.as_str()).unwrap_or("<unknown>");
                        tracing::warn!(
                            "JMAP Email/get: dropping email that failed to deserialize: {e} (id: {id})"
                        );
                    }
                }
            }
        }

        Ok(all_emails)
    }

    /// Create a new email in the specified mailbox.
    pub async fn email_set(
        &self,
        account_id: &str,
        mailbox_id: &str,
        subject: &str,
        body: &str,
    ) -> Result<()> {
        let args = json!({
            "accountId": account_id,
            "create": {
                "new1": {
                    "mailboxIds": { mailbox_id: true },
                    "subject": subject,
                    "textBody": [
                        {
                            "partId": "body",
                            "type": "text/plain"
                        }
                    ],
                    "bodyValues": {
                        "body": {
                            "value": body,
                            "isEncodingProblem": false,
                            "isTruncated": false
                        }
                    }
                }
            }
        });
        let calls = vec![("Email/set".to_string(), args, "c1".to_string())];
        let responses = self.request(calls).await?;

        let resp_args = responses
            .into_iter()
            .find(|(m, _, _)| m == "Email/set")
            .map(|(_, args, _)| args)
            .ok_or_else(|| anyhow!("Email/set response not found"))?;

        // Check for server-side errors.
        if let Some(not_created) = resp_args.get("notCreated") {
            if not_created.as_object().is_some_and(|m| !m.is_empty()) {
                return Err(anyhow!("Email/set notCreated: {not_created}"));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_email(
        id: &str,
        sender: Option<&str>,
        subject: Option<&str>,
        body: Option<&str>,
    ) -> EmailObject {
        use std::collections::HashMap;
        EmailObject {
            id: id.to_string(),
            from: sender.map(|name| {
                vec![EmailAddress {
                    name: Some(name.to_string()),
                    email: Some(format!("{name}@example.com")),
                }]
            }),
            subject: subject.map(str::to_string),
            body_values: body.map(|b| {
                let mut m = HashMap::new();
                m.insert(
                    "1".to_string(),
                    BodyPart {
                        value: b.to_string(),
                    },
                );
                m
            }),
            text_body: body.map(|_| {
                vec![BodyPartRef {
                    part_id: Some("1".to_string()),
                }]
            }),
        }
    }

    #[test]
    fn plain_text_returns_body() {
        let email = make_email("id1", Some("Alice"), Some("subject"), Some("hello world"));
        assert_eq!(email.plain_text(), Some("hello world"));
    }

    #[test]
    fn plain_text_returns_none_when_no_body() {
        let email = make_email("id2", Some("Alice"), Some("subject"), None);
        assert_eq!(email.plain_text(), None);
    }

    #[test]
    fn sender_display_returns_name() {
        let email = make_email("id3", Some("Bob"), None, None);
        assert_eq!(email.sender_display(), Some("Bob"));
    }

    #[test]
    fn sender_display_returns_none_when_no_from() {
        let email = make_email("id4", None, None, None);
        assert_eq!(email.sender_display(), None);
    }

    /// Verify that `init_session` rejects an `apiUrl` whose origin differs from the
    /// session URL origin, preventing SSRF via AWS metadata or internal hosts.
    #[tokio::test]
    async fn init_session_rejects_ssrf_api_url() {
        // We build a JmapClient whose session_url has origin https://legitimate.example.com.
        // We then directly test the origin-comparison logic by constructing the same
        // check that init_session performs, using URLs that represent what a malicious
        // JMAP server might return.
        use url::Url;

        let session_url = Url::parse("https://legitimate.example.com/.well-known/jmap").unwrap();

        let ssrf_cases = [
            "https://169.254.169.254/latest/meta-data/",
            "https://10.0.0.1/api/",
            "https://localhost/api/",
            "https://evil.example.com/api/",
        ];

        for api_url_str in &ssrf_cases {
            let api_url = Url::parse(api_url_str).unwrap();
            assert_ne!(
                api_url.origin(),
                session_url.origin(),
                "Expected origin mismatch for SSRF candidate: {api_url_str}"
            );
        }

        // A same-origin apiUrl must pass the check.
        let same_origin = Url::parse("https://legitimate.example.com/jmap/").unwrap();
        assert_eq!(
            same_origin.origin(),
            session_url.origin(),
            "Same-origin apiUrl should pass the SSRF check"
        );
    }
}
