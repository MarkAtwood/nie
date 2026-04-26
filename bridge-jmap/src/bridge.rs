//! JMAP ↔ nie bridge: bidirectional message forwarding.
//!
//! # Architecture
//!
//! ```text
//! JMAP server ─── polling loop ──► nie broadcast
//!      ▲                                  │
//!      │                                  ▼
//! Email/set ◄────────────────────── nie deliver
//! ```
//!
//! A background tokio task polls the JMAP mailbox every `poll_interval_secs`
//! seconds and forwards new emails to the nie relay as Chat messages.
//! When the nie relay delivers messages, we create a new email in the JMAP
//! mailbox via Email/set.

use anyhow::Result;
use nie_core::messages::{pad, unpad, ClearMessage};
use nie_core::protocol::{rpc_methods, BroadcastParams, DeliverParams, JsonRpcRequest};
use nie_core::transport::{next_request_id, ClientEvent};
use serde_json::Value;
use std::collections::{HashSet, VecDeque};
use std::path::Path;
use std::sync::{Arc, Mutex};
use tokio::time::{interval, Duration};

use crate::config::BridgeConfig;
use crate::jmap::JmapClient;

/// Bounded set of recently-seen JMAP email IDs used to avoid reprocessing.
///
/// Capped at 1000 entries; the oldest entry is evicted when the cap is reached.
/// Each poll fetches at most 50 IDs, so 1000 entries covers 20 full-scan
/// cycles before the first eviction.
///
/// Persisted to a JSON file so that seen IDs survive process restarts and
/// emails are not replayed on the next startup.
struct SeenIds {
    ids: VecDeque<String>,
    set: HashSet<String>,
    /// Path to the JSON file used for persistence. `None` means no persistence.
    persist_path: Option<std::path::PathBuf>,
}

impl SeenIds {
    /// Load seen IDs from `path`, creating the set from scratch if the file
    /// does not exist yet.  Logs a warning and returns an empty set on any
    /// parse error to avoid blocking startup.
    fn load_or_new(path: &Path) -> Self {
        let mut s = Self {
            ids: VecDeque::new(),
            set: HashSet::new(),
            persist_path: Some(path.to_path_buf()),
        };
        match std::fs::read(path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // First run — no state file yet; start fresh.
            }
            Err(e) => {
                tracing::warn!("seen_ids: failed to read {:?}: {e}; starting fresh", path);
            }
            Ok(bytes) => match serde_json::from_slice::<Vec<String>>(&bytes) {
                Ok(loaded) => {
                    for id in loaded {
                        s.set.insert(id.clone());
                        s.ids.push_back(id);
                    }
                }
                Err(e) => {
                    tracing::warn!("seen_ids: failed to parse {:?}: {e}; starting fresh", path);
                }
            },
        }
        s
    }

    fn contains(&self, id: &str) -> bool {
        self.set.contains(id)
    }

    fn insert(&mut self, id: String) {
        const MAX: usize = 1000;
        if self.ids.len() >= MAX {
            if let Some(old) = self.ids.pop_front() {
                self.set.remove(&old);
            }
        }
        self.set.insert(id.clone());
        self.ids.push_back(id);
        self.persist();
    }

    /// Write the current ID list to the persistence file.
    ///
    /// Writes to a `.tmp` sibling first, then renames atomically so that a
    /// crash mid-write never leaves a truncated file.  Logs a warning on error
    /// rather than propagating — persistence failures are non-fatal.
    fn persist(&self) {
        let Some(path) = &self.persist_path else {
            return;
        };
        let ids: Vec<&str> = self.ids.iter().map(String::as_str).collect();
        let json = match serde_json::to_vec(&ids) {
            Ok(j) => j,
            Err(e) => {
                tracing::warn!("seen_ids: failed to serialize: {e}");
                return;
            }
        };
        // Write to a tmp file then rename for atomicity.
        let mut tmp_path = path.to_path_buf();
        tmp_path.set_extension("json.tmp");
        if let Err(e) = std::fs::write(&tmp_path, &json) {
            tracing::warn!("seen_ids: failed to write {:?}: {e}", tmp_path);
            return;
        }
        if let Err(e) = std::fs::rename(&tmp_path, path) {
            tracing::warn!(
                "seen_ids: failed to rename {:?} → {:?}: {e}",
                tmp_path,
                path
            );
        }
    }
}

/// Format a nie message as an email subject/body for delivery to the JMAP mailbox.
pub fn format_subject(sender_pub_id: &str, prefix: Option<&str>) -> String {
    let short_id = &sender_pub_id[..sender_pub_id.len().min(8)];
    match prefix {
        Some(p) => format!("{p} nie/{short_id}"),
        None => format!("nie/{short_id}"),
    }
}

/// Format a JMAP email for forwarding to nie.
pub fn format_for_nie(sender: &str, subject: Option<&str>, text: &str) -> String {
    match subject {
        Some(s) => format!("[JMAP/{sender} | {s}] {text}"),
        None => format!("[JMAP/{sender}] {text}"),
    }
}

// ---- Main bridge loop ----

pub async fn run(config: &BridgeConfig) -> Result<()> {
    let identity = nie_core::keyfile::load_identity(&config.keyfile, false)?;
    let own_pub_id = identity.pub_id().0.clone();

    // Connect to the nie relay with transparent reconnection.
    let mut conn =
        nie_core::transport::connect_with_retry(config.relay_url.clone(), identity, false, None);

    // JMAP client.
    let mut jmap = JmapClient::new(&config.jmap_session_url, &config.jmap_bearer_token);
    jmap.init_session().await?;
    let jmap = Arc::new(jmap);

    let account_id = config.jmap_account_id.clone();
    let mailbox_id = config.jmap_mailbox_id.clone();
    let bridge_prefix = config.bridge_prefix.clone();
    let mailbox_name = config.mailbox_name.clone();
    let poll_interval_secs = config.poll_interval_secs;

    // Track seen email IDs to avoid reprocessing on each poll (bounded at 1000).
    // Load from disk so IDs seen before a restart are not replayed.
    let seen_ids_path = std::path::Path::new(&config.seen_ids_path);
    let seen_ids: Arc<Mutex<SeenIds>> = Arc::new(Mutex::new(SeenIds::load_or_new(seen_ids_path)));

    // Channel: JMAP poll → nie broadcast.
    let (jmap_tx, mut jmap_rx) = tokio::sync::mpsc::channel::<String>(64);

    // Background polling task: watches the JMAP mailbox for new emails.
    {
        let jmap = Arc::clone(&jmap);
        let seen_ids = Arc::clone(&seen_ids);
        let account_id = account_id.clone();
        let mailbox_id = mailbox_id.clone();
        let mailbox_name = mailbox_name.clone();
        let tx = jmap_tx;
        tokio::spawn(async move {
            let mut ticker = interval(Duration::from_secs(poll_interval_secs));
            loop {
                ticker.tick().await;

                let (ids, _) = match jmap.email_query(&account_id, &mailbox_id, None).await {
                    Ok(v) => v,
                    Err(e) => {
                        tracing::warn!("JMAP email_query failed: {e}");
                        continue;
                    }
                };

                // Filter to IDs we haven't seen yet (read-only check — do not
                // insert yet; we only mark an ID seen after a successful send
                // so that channel-full drops are retried on the next poll).
                let new_ids: Vec<String> = {
                    let seen = seen_ids.lock().unwrap_or_else(|e| e.into_inner());
                    ids.into_iter()
                        .filter(|id| !seen.contains(id.as_str()))
                        .collect()
                };

                if !new_ids.is_empty() {
                    match jmap.email_get(&account_id, &new_ids).await {
                        Ok(emails) => {
                            for email in emails {
                                let sender =
                                    email.sender_display().unwrap_or("unknown").to_string();
                                let text = match email.plain_text() {
                                    Some(t) => t.trim().to_string(),
                                    None => {
                                        // No text body — mark seen so we don't retry endlessly.
                                        seen_ids
                                            .lock()
                                            .unwrap_or_else(|e| e.into_inner())
                                            .insert(email.id.clone());
                                        continue;
                                    }
                                };
                                if text.is_empty() {
                                    seen_ids
                                        .lock()
                                        .unwrap_or_else(|e| e.into_inner())
                                        .insert(email.id.clone());
                                    continue;
                                }
                                let display_subject = email.subject.as_deref();
                                let mbox = mailbox_name.as_deref().unwrap_or(&sender);
                                let nie_text = format_for_nie(mbox, display_subject, &text);
                                if tx.try_send(nie_text).is_ok() {
                                    // Only mark seen after successful enqueue so that
                                    // a channel-full drop is retried on the next poll.
                                    seen_ids
                                        .lock()
                                        .unwrap_or_else(|e| e.into_inner())
                                        .insert(email.id.clone());
                                } else {
                                    tracing::warn!("JMAP→nie channel full; email will retry");
                                }
                            }
                        }
                        Err(e) => {
                            tracing::warn!("JMAP email_get failed: {e}");
                            // Mark all requested IDs as seen so a persistently
                            // malformed or undecodable response is not retried
                            // forever.  The warn above records the IDs via the
                            // new_ids value logged in context.
                            let mut seen = seen_ids.lock().unwrap_or_else(|e| e.into_inner());
                            for id in &new_ids {
                                tracing::warn!(
                                    "skipping email {id} after fetch error; will not retry"
                                );
                                seen.insert(id.clone());
                            }
                        }
                    }
                }
            }
        });
    }

    tracing::info!("bridge-jmap connected to relay as {}", &own_pub_id[..8]);

    // Main event loop.
    loop {
        tokio::select! {
            // JMAP email → nie broadcast.
            maybe_text = jmap_rx.recv() => {
                let Some(text) = maybe_text else { break };
                let payload = serde_json::to_vec(&ClearMessage::Chat { text }).unwrap();
                let Ok(padded) = pad(&payload) else {
                    tracing::warn!("JMAP message too large to pad; dropped");
                    continue;
                };
                let Ok(rpc) = JsonRpcRequest::new(
                    next_request_id(),
                    rpc_methods::BROADCAST,
                    BroadcastParams { payload: padded },
                ) else {
                    continue;
                };
                if conn.tx.send(rpc).await.is_err() {
                    tracing::warn!("relay disconnected while sending");
                    break;
                }
            }
            // nie relay event → JMAP email.
            maybe_event = conn.rx.recv() => {
                let Some(event) = maybe_event else { break };
                match event {
                    ClientEvent::Message(notif) => {
                        if notif.method == rpc_methods::DELIVER {
                            handle_nie_deliver(
                                notif.params,
                                &own_pub_id,
                                &jmap,
                                &account_id,
                                &mailbox_id,
                                bridge_prefix.as_deref(),
                            )
                            .await;
                        }
                    }
                    ClientEvent::Reconnecting { delay_secs } => {
                        tracing::info!("relay reconnecting in {delay_secs}s");
                    }
                    ClientEvent::Disconnected => {
                        tracing::error!("relay disconnected");
                        break;
                    }
                    _ => {}
                }
            }
        }
    }
    Ok(())
}

async fn handle_nie_deliver(
    params: Option<Value>,
    own_pub_id: &str,
    jmap: &JmapClient,
    account_id: &str,
    mailbox_id: &str,
    bridge_prefix: Option<&str>,
) {
    let Some(params) = params else { return };
    let Ok(deliver) = serde_json::from_value::<DeliverParams>(params) else {
        return;
    };
    if deliver.from == own_pub_id {
        return; // skip own echo
    }
    let Ok(msg) = unpad(&deliver.payload) else {
        return;
    };
    let Ok(clear) = serde_json::from_slice::<ClearMessage>(&msg) else {
        return;
    };
    let ClearMessage::Chat { text } = clear else {
        return;
    };
    let subject = format_subject(&deliver.from, bridge_prefix);
    if let Err(e) = jmap
        .email_set(account_id, mailbox_id, &subject, &text)
        .await
    {
        tracing::warn!("JMAP email_set failed: {e}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_subject_with_prefix() {
        let s = format_subject("abcdef1234567890", Some("[nie]"));
        assert_eq!(s, "[nie] nie/abcdef12");
    }

    #[test]
    fn format_subject_without_prefix() {
        let s = format_subject("abcdef1234567890", None);
        assert_eq!(s, "nie/abcdef12");
    }

    #[test]
    fn format_subject_short_id() {
        let s = format_subject("abc", None);
        assert_eq!(s, "nie/abc");
    }

    #[test]
    fn format_for_nie_with_subject() {
        let s = format_for_nie("Alice", Some("Re: hi"), "hello");
        assert_eq!(s, "[JMAP/Alice | Re: hi] hello");
    }

    #[test]
    fn format_for_nie_without_subject() {
        let s = format_for_nie("Alice", None, "hello");
        assert_eq!(s, "[JMAP/Alice] hello");
    }
}
