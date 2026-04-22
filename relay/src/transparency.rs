use axum::{http::HeaderMap, response::IntoResponse};
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EntryType {
    Subpoena,
    CourtOrder,
    Preservation,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EntryStatus {
    Responded,
    Pending,
    Challenged,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct TransparencyEntry {
    pub id: String,
    pub entity: String,
    #[serde(rename = "type")]
    pub entry_type: EntryType,
    pub received: String,
    pub status: EntryStatus,
    pub notes: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct TransparencyLog {
    pub entries: Vec<TransparencyEntry>,
}

fn render_html(log: &TransparencyLog) -> String {
    let body = if log.entries.is_empty() {
        "<p>No legal demands have been received.</p>".to_string()
    } else {
        let rows: String = log
            .entries
            .iter()
            .map(|e| {
                let type_str = match e.entry_type {
                    EntryType::Subpoena => "subpoena",
                    EntryType::CourtOrder => "court_order",
                    EntryType::Preservation => "preservation",
                };
                let status_str = match e.status {
                    EntryStatus::Responded => "responded",
                    EntryStatus::Pending => "pending",
                    EntryStatus::Challenged => "challenged",
                };
                format!(
                    "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                    html_escape(&e.id),
                    html_escape(&e.entity),
                    type_str,
                    html_escape(&e.received),
                    status_str,
                    html_escape(&e.notes),
                )
            })
            .collect();
        format!(
            "<table>\
            <thead><tr>\
            <th>ID</th><th>Requesting Entity</th><th>Type</th>\
            <th>Date Received</th><th>Status</th><th>Notes</th>\
            </tr></thead>\
            <tbody>{rows}</tbody>\
            </table>"
        )
    };

    format!(
        "<!DOCTYPE html>\
        <html lang=\"en\">\
        <head><meta charset=\"utf-8\"><title>nie relay \u{2014} Legal Transparency Log</title></head>\
        <body>\
        <h1>nie relay \u{2014} Legal Transparency Log</h1>\
        {body}\
        <footer><p><a href=\"/legal\">LEGAL.md</a></p></footer>\
        </body>\
        </html>"
    )
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

pub async fn transparency_handler(headers: HeaderMap) -> impl IntoResponse {
    let file_path = std::env::var("TRANSPARENCY_FILE")
        .unwrap_or_else(|_| "transparency.json".to_string());

    let log: TransparencyLog = match std::fs::read_to_string(&file_path) {
        Ok(content) => {
            serde_json::from_str(&content).unwrap_or(TransparencyLog { entries: vec![] })
        }
        Err(_) => TransparencyLog { entries: vec![] },
    };

    let wants_html = headers
        .get("accept")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|a| a.contains("text/html"));

    if wants_html {
        let html = render_html(&log);
        (
            [
                (
                    axum::http::header::CACHE_CONTROL,
                    "no-store",
                ),
                (
                    axum::http::header::CONTENT_TYPE,
                    "text/html; charset=utf-8",
                ),
            ],
            html,
        )
            .into_response()
    } else {
        (
            [(axum::http::header::CACHE_CONTROL, "no-store")],
            axum::Json(log),
        )
            .into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_entry(id: &str, entity: &str) -> TransparencyEntry {
        TransparencyEntry {
            id: id.to_string(),
            entity: entity.to_string(),
            entry_type: EntryType::Subpoena,
            received: "2026-01-01".to_string(),
            status: EntryStatus::Responded,
            notes: "Test note.".to_string(),
        }
    }

    #[test]
    fn html_empty_log() {
        let log = TransparencyLog { entries: vec![] };
        let html = render_html(&log);
        assert!(html.contains("No legal demands have been received."));
        assert!(html.contains("charset=\"utf-8\""));
        assert!(html.contains("Legal Transparency Log"));
        assert!(html.contains("/legal"));
    }

    #[test]
    fn html_with_entries() {
        let log = TransparencyLog {
            entries: vec![make_entry("LEG-0001", "Example Agency")],
        };
        let html = render_html(&log);
        assert!(html.contains("LEG-0001"));
        assert!(html.contains("Example Agency"));
        assert!(html.contains("subpoena"));
        assert!(html.contains("responded"));
        assert!(html.contains("Test note."));
        assert!(html.contains("<table>"));
    }

    #[test]
    fn html_escape_special_chars() {
        let log = TransparencyLog {
            entries: vec![make_entry("LEG-0002", "<Evil & \"Agency\">")],
        };
        let html = render_html(&log);
        assert!(!html.contains("<Evil"));
        assert!(html.contains("&lt;Evil &amp; &quot;Agency&quot;&gt;"));
    }

    #[test]
    fn json_round_trip() {
        let json = r#"{"entries":[{"id":"LEG-0001","entity":"Example Agency","type":"subpoena","received":"2026-01-01","status":"responded","notes":"Test."}]}"#;
        let log: TransparencyLog = serde_json::from_str(json).unwrap();
        assert_eq!(log.entries.len(), 1);
        assert_eq!(log.entries[0].id, "LEG-0001");
        let out = serde_json::to_string(&log).unwrap();
        assert!(out.contains("\"type\":\"subpoena\""));
        assert!(out.contains("\"status\":\"responded\""));
    }

    #[test]
    fn empty_json_on_missing_file() {
        let log: TransparencyLog =
            serde_json::from_str("not valid json").unwrap_or(TransparencyLog { entries: vec![] });
        assert!(log.entries.is_empty());
    }
}
