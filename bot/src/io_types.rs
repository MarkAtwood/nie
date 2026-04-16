use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::io::Write;

fn utc_now() -> String {
    chrono::Utc::now().to_rfc3339()
}

/// Events emitted by the bot on stdout as NDJSON (one JSON object per line).
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum BotEvent {
    Connected {
        relay_url: String,
        pub_id: String,
        ts: String,
    },
    Disconnected {
        reason: String,
        ts: String,
    },
    Reconnecting {
        delay_secs: u64,
        ts: String,
    },
    MessageReceived {
        from: String,
        text: String,
        /// Always empty string in Phase 4f — DeliverParams does not carry a message ID.
        message_id: String,
        ts: String,
    },
    UserJoined {
        pub_id: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        nickname: Option<String>,
        ts: String,
    },
    UserLeft {
        pub_id: String,
        ts: String,
    },
    PaymentRequest {
        session_id: String,
        from: String,
        chain: String,
        /// Human-readable amount string from the PaymentAction (e.g. "0.1", "100").
        amount: String,
        ts: String,
    },
    ScriptOutput {
        command: String,
        exit_code: i32,
        stdout: String,
        stderr: String,
        ts: String,
    },
    Error {
        reason: String,
        ts: String,
    },
}

impl BotEvent {
    /// Emit this event as a single NDJSON line to stdout.
    /// Uses lock() to prevent interleaving with concurrent writes.
    pub fn emit(&self) -> Result<()> {
        let json = serde_json::to_string(self)?;
        let stdout = std::io::stdout();
        let mut handle = stdout.lock();
        writeln!(handle, "{json}")?;
        Ok(())
    }

    pub fn connected(relay_url: String, pub_id: String) -> Self {
        Self::Connected {
            relay_url,
            pub_id,
            ts: utc_now(),
        }
    }

    pub fn disconnected(reason: impl Into<String>) -> Self {
        Self::Disconnected {
            reason: reason.into(),
            ts: utc_now(),
        }
    }

    pub fn error(reason: impl Into<String>) -> Self {
        Self::Error {
            reason: reason.into(),
            ts: utc_now(),
        }
    }

    pub fn message_received(from: String, text: String, message_id: String) -> Self {
        Self::MessageReceived {
            from,
            text,
            message_id,
            ts: utc_now(),
        }
    }

    pub fn user_joined(pub_id: String, nickname: Option<String>) -> Self {
        Self::UserJoined {
            pub_id,
            nickname,
            ts: utc_now(),
        }
    }

    pub fn user_left(pub_id: String) -> Self {
        Self::UserLeft {
            pub_id,
            ts: utc_now(),
        }
    }
}

/// Commands accepted by the bot on stdin as NDJSON (one JSON object per line).
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum BotCommand {
    Send { text: String },
    SetNickname { nickname: String },
    Whoami,
    Users,
    Quit,
}

impl BotCommand {
    /// Read exactly one BotCommand from stdin.
    /// Returns `Ok(None)` on EOF. Returns `Err` on I/O or parse error.
    ///
    /// # Warning: call at most once
    ///
    /// Each call constructs a new `BufReader` over stdin. Any bytes buffered
    /// by a previous call are lost. For repeated reading, use the `stdin_reader`
    /// module, which owns a single `BufReader` for the process lifetime.
    pub async fn read_next() -> Result<Option<Self>> {
        use tokio::io::{AsyncBufReadExt, BufReader};
        let stdin = tokio::io::stdin();
        let mut reader = BufReader::new(stdin);
        let mut line = String::new();
        let n = reader.read_line(&mut line).await?;
        if n == 0 {
            return Ok(None); // EOF — clean shutdown signal
        }
        let trimmed = line.trim();
        if trimmed.is_empty() {
            return Err(anyhow::anyhow!("empty line"));
        }
        Ok(Some(serde_json::from_str(trimmed)?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bot_event_message_received_type_tag() {
        let event = BotEvent::MessageReceived {
            from: "abc".into(),
            text: "hi".into(),
            message_id: "msg1".into(),
            ts: "2026-01-01T00:00:00+00:00".into(),
        };
        let json = serde_json::to_string(&event).unwrap();
        assert!(
            json.contains(r#""type":"message_received""#),
            "expected type tag not found in: {json}"
        );
        assert!(
            json.contains(r#""from":"abc""#),
            "expected from field not found in: {json}"
        );
        assert!(
            json.contains(r#""text":"hi""#),
            "expected text field not found in: {json}"
        );
    }

    #[test]
    fn test_bot_event_user_joined_no_nickname() {
        let event = BotEvent::UserJoined {
            pub_id: "deadbeef".into(),
            nickname: None,
            ts: "2026-01-01T00:00:00+00:00".into(),
        };
        let json = serde_json::to_string(&event).unwrap();
        assert!(
            !json.contains("nickname"),
            "nickname key must be absent when None, but found in: {json}"
        );
    }

    #[test]
    fn test_bot_event_user_joined_with_nickname() {
        let event = BotEvent::UserJoined {
            pub_id: "deadbeef".into(),
            nickname: Some("Alice".into()),
            ts: "2026-01-01T00:00:00+00:00".into(),
        };
        let json = serde_json::to_string(&event).unwrap();
        assert!(
            json.contains(r#""nickname":"Alice""#),
            "expected nickname field not found in: {json}"
        );
    }

    #[test]
    fn test_bot_event_all_variants_have_type_field() {
        let variants: Vec<BotEvent> = vec![
            BotEvent::Connected {
                relay_url: "wss://example.com/ws".into(),
                pub_id: "aaa".into(),
                ts: "2026-01-01T00:00:00+00:00".into(),
            },
            BotEvent::Disconnected {
                reason: "timeout".into(),
                ts: "2026-01-01T00:00:00+00:00".into(),
            },
            BotEvent::Reconnecting {
                delay_secs: 5,
                ts: "2026-01-01T00:00:00+00:00".into(),
            },
            BotEvent::MessageReceived {
                from: "bbb".into(),
                text: "hello".into(),
                message_id: "m1".into(),
                ts: "2026-01-01T00:00:00+00:00".into(),
            },
            BotEvent::UserJoined {
                pub_id: "ccc".into(),
                nickname: None,
                ts: "2026-01-01T00:00:00+00:00".into(),
            },
            BotEvent::UserLeft {
                pub_id: "ddd".into(),
                ts: "2026-01-01T00:00:00+00:00".into(),
            },
            BotEvent::PaymentRequest {
                session_id: "sess1".into(),
                from: "eee".into(),
                chain: "zcash".into(),
                amount: "100000".into(),
                ts: "2026-01-01T00:00:00+00:00".into(),
            },
            BotEvent::ScriptOutput {
                command: "echo hi".into(),
                exit_code: 0,
                stdout: "hi\n".into(),
                stderr: String::new(),
                ts: "2026-01-01T00:00:00+00:00".into(),
            },
            BotEvent::Error {
                reason: "something failed".into(),
                ts: "2026-01-01T00:00:00+00:00".into(),
            },
        ];
        for variant in &variants {
            let json = serde_json::to_string(variant).unwrap();
            assert!(
                json.contains(r#""type":"#),
                "variant {:?} missing \"type\" field in: {json}",
                variant
            );
        }
    }

    #[test]
    fn test_bot_command_send_deserialize() {
        let input = r#"{"cmd":"send","text":"hello world"}"#;
        let result: Result<BotCommand, _> = serde_json::from_str(input);
        assert!(result.is_ok(), "expected Ok, got: {:?}", result.err());
        match result.unwrap() {
            BotCommand::Send { text } => {
                assert_eq!(text, "hello world");
            }
            other => panic!("expected BotCommand::Send, got: {other:?}"),
        }
    }

    #[test]
    fn test_bot_command_unknown_cmd_returns_err() {
        let input = r#"{"cmd":"explode"}"#;
        let result: Result<BotCommand, _> = serde_json::from_str(input);
        assert!(
            result.is_err(),
            "expected Err for unknown cmd, got Ok: {:?}",
            result.ok()
        );
    }
}
