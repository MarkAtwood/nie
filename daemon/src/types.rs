// Variants and error types are constructed by later beads (relay connector, HTTP handlers).
#![allow(dead_code)]

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserInfo {
    pub pub_id: String,
    pub display_name: String,
    pub sequence: u64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum DaemonEvent {
    MessageReceived {
        from: String,
        from_display_name: String,
        text: String,
        timestamp: String,
        message_id: String,
    },
    UserJoined {
        pub_id: String,
        display_name: String,
        sequence: u64,
        timestamp: String,
    },
    UserLeft {
        pub_id: String,
        display_name: String,
        timestamp: String,
    },
    DirectoryUpdated {
        online: Vec<UserInfo>,
        offline: Vec<UserInfo>,
        timestamp: String,
    },
    MlsStateChanged {
        active: bool,
        epoch: u64,
        timestamp: String,
    },
    ConnectionStateChanged {
        status: String,
        relay_url: String,
        timestamp: String,
    },
    PaymentUpdate {
        session_id: String,
        peer_pub_id: String,
        peer_display_name: String,
        state: String,
        action: String,
        chain: String,
        amount_zatoshi: u64,
        timestamp: String,
    },
    Typing {
        /// pub_id of the user who started/stopped typing.
        from: String,
        /// JMAP chat ID (channel) where the typing occurred.
        chat_id: String,
        /// `true` = started typing; `false` = stopped typing.
        typing: bool,
        timestamp: String,
    },
    MessageRetracted {
        message_id: String,
        from_pub_id: String,
        for_all: bool,
        timestamp: String,
    },
}

#[derive(Debug, thiserror::Error)]
pub enum DaemonError {
    #[error("config error: {0}")]
    Config(#[from] std::io::Error),
    #[error("relay connection error: {0}")]
    RelayConnect(String),
    #[error("auth error: {0}")]
    Auth(String),
    #[error("serialization error: {0}")]
    Serialize(#[from] serde_json::Error),
    #[error("wallet not initialized")]
    WalletNotInitialized,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_message_received_type_tag() {
        let event = DaemonEvent::MessageReceived {
            from: "a".repeat(64),
            from_display_name: "Alice".to_string(),
            text: "hello".to_string(),
            timestamp: "2026-04-19T14:30:00Z".to_string(),
            message_id: "550e8400-e29b-41d4-a716-446655440000".to_string(),
        };
        let json = serde_json::to_string(&event).unwrap();
        assert!(
            json.contains("\"type\":\"message_received\""),
            "json={json}"
        );
    }

    #[test]
    fn test_user_joined_type_tag() {
        let event = DaemonEvent::UserJoined {
            pub_id: "b".repeat(64),
            display_name: "Bob".to_string(),
            sequence: 1,
            timestamp: "2026-04-19T14:30:00Z".to_string(),
        };
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("\"type\":\"user_joined\""), "json={json}");
    }

    #[test]
    fn test_typing_type_tag_and_fields() {
        // Oracle: serde tag = "typing" (snake_case of variant name), fields are stable
        // wire contract consumed by the JMAP SSE client.
        let event = DaemonEvent::Typing {
            from: "a".repeat(64),
            chat_id: "01ARZ3NDEKTSV4RRFFQ69G5FAV".to_string(),
            typing: true,
            timestamp: "2026-04-23T10:00:00Z".to_string(),
        };
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("\"type\":\"typing\""), "json={json}");
        assert!(json.contains("\"typing\":true"), "json={json}");
        assert!(json.contains("\"chat_id\""), "json={json}");
        assert!(json.contains("\"from\""), "json={json}");
    }

    #[test]
    fn test_connection_state_changed_type_tag() {
        let event = DaemonEvent::ConnectionStateChanged {
            status: "connected".to_string(),
            relay_url: "ws://localhost:3210/ws".to_string(),
            timestamp: "2026-04-19T14:30:00Z".to_string(),
        };
        let json = serde_json::to_string(&event).unwrap();
        assert!(
            json.contains("\"type\":\"connection_state_changed\""),
            "json={json}"
        );
    }
}
