use nie_core::messages::{ClearMessage, PaymentAction};
use nie_core::protocol::{
    rpc_methods, DeliverParams, JsonRpcNotification, UserJoinedParams, UserLeftParams,
    WhisperDeliverParams,
};

use crate::io_types::BotEvent;

/// Convert an incoming relay JSON-RPC notification into a BotEvent (if any).
///
/// Returns `Ok(None)` for notifications that produce no user-visible event
/// (e.g., `directory_list` is handled separately by the main loop, unknown
/// methods are silently ignored).
///
/// Never returns `Err` for unknown methods or malformed payloads — those are
/// logged at debug level and cause `Ok(None)` to be returned.
pub fn dispatch(notif: &JsonRpcNotification) -> Option<BotEvent> {
    match notif.method.as_str() {
        rpc_methods::DELIVER => dispatch_deliver(notif),
        rpc_methods::WHISPER_DELIVER => dispatch_whisper_deliver(notif),
        rpc_methods::USER_JOINED => dispatch_user_joined(notif),
        rpc_methods::USER_LEFT => dispatch_user_left(notif),
        rpc_methods::DIRECTORY_LIST => None, // caller handles directory
        _ => None,                           // unknown method: ignore silently
    }
}

fn dispatch_deliver(notif: &JsonRpcNotification) -> Option<BotEvent> {
    let params: DeliverParams = parse_params(notif)?;
    dispatch_payload(&params.from, &params.payload)
}

fn dispatch_whisper_deliver(notif: &JsonRpcNotification) -> Option<BotEvent> {
    let params: WhisperDeliverParams = parse_params(notif)?;
    dispatch_payload(&params.from, &params.payload)
}

fn dispatch_payload(from: &str, payload: &[u8]) -> Option<BotEvent> {
    if from.is_empty() {
        tracing::warn!("deliver: empty from field, dropping");
        return None;
    }
    // Payload is opaque bytes — attempt to deserialize as ClearMessage.
    // Failure is expected once MLS ciphertext lands; debug log only.
    let msg: ClearMessage = match serde_json::from_slice(payload) {
        Ok(m) => m,
        Err(e) => {
            tracing::warn!("payload not a ClearMessage (unexpected pre-MLS): {e}");
            return None;
        }
    };
    match msg {
        ClearMessage::Chat { text } => Some(BotEvent::message_received(
            from.to_string(),
            text,
            String::new(), // message_id not carried in DeliverParams; leave empty
        )),
        ClearMessage::Payment { session_id, action } => {
            if let PaymentAction::Request { chain, amount_zatoshi } = action {
                // Use canonical lowercase wire names, not Display (which gives "ZEC"/"XMR").
                let chain_str = match chain {
                    nie_core::messages::Chain::Zcash => "zcash",
                    nie_core::messages::Chain::Monero => "monero",
                    nie_core::messages::Chain::Mobilecoin => "mobilecoin",
                }
                .to_owned();
                Some(BotEvent::PaymentRequest {
                    session_id: session_id.to_string(),
                    from: from.to_string(),
                    chain: chain_str,
                    amount: nie_core::zatoshi_to_zec_string(amount_zatoshi),
                    ts: chrono::Utc::now().to_rfc3339(),
                })
            } else {
                None // other PaymentAction variants not surfaced as events
            }
        }
        ClearMessage::Ack { .. } | ClearMessage::Profile { .. } => None,
    }
}

fn dispatch_user_joined(notif: &JsonRpcNotification) -> Option<BotEvent> {
    let params: UserJoinedParams = parse_params(notif)?;
    Some(BotEvent::user_joined(params.pub_id, params.nickname))
}

fn dispatch_user_left(notif: &JsonRpcNotification) -> Option<BotEvent> {
    let params: UserLeftParams = parse_params(notif)?;
    Some(BotEvent::user_left(params.pub_id))
}

/// Parse notification params into `T`. Returns `None` (with debug log) on failure.
fn parse_params<T: serde::de::DeserializeOwned>(notif: &JsonRpcNotification) -> Option<T> {
    let params = notif.params.as_ref()?;
    match serde_json::from_value(params.clone()) {
        Ok(v) => Some(v),
        Err(e) => {
            tracing::warn!("failed to parse params for {}: {e}", notif.method);
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nie_core::messages::Chain;
    use nie_core::protocol::JsonRpcNotification;
    use serde_json::json;
    use uuid::Uuid;

    fn make_notif(method: &str, params: serde_json::Value) -> JsonRpcNotification {
        JsonRpcNotification {
            version: "2.0".into(),
            method: method.into(),
            params: Some(params),
        }
    }

    // --- dispatch_deliver ---

    /// Oracle: a ClearMessage::Chat serialized to JSON, base64-encoded as the
    /// payload, then delivered via a `deliver` notification. Expected: BotEvent::MessageReceived.
    #[test]
    fn deliver_chat_produces_message_received() {
        // Oracle: serde_json output of ClearMessage::Chat — verified against
        // ClearMessage serde tag ("type":"chat") from messages.rs docs.
        let payload_bytes = serde_json::to_vec(&ClearMessage::Chat {
            text: "hello".into(),
        })
        .unwrap();
        let b64 = base64_encode(&payload_bytes);
        let notif = make_notif(
            rpc_methods::DELIVER,
            json!({"from": "aabbcc", "payload": b64}),
        );
        let event = dispatch(&notif);
        match event {
            Some(BotEvent::MessageReceived { from, text, .. }) => {
                assert_eq!(from, "aabbcc");
                assert_eq!(text, "hello");
            }
            other => panic!("expected MessageReceived, got: {other:?}"),
        }
    }

    /// Oracle: a ClearMessage::Payment / Request serialized to JSON, base64-encoded.
    /// Expected: BotEvent::PaymentRequest with chain = "zcash".
    #[test]
    fn deliver_payment_request_produces_payment_request_event() {
        let session_id = Uuid::nil(); // known fixed UUID for determinism
        let payload_bytes = serde_json::to_vec(&ClearMessage::Payment {
            session_id,
            action: PaymentAction::Request {
                chain: Chain::Zcash,
                amount_zatoshi: 4_200_000_000, // 42 ZEC
            },
        })
        .unwrap();
        let b64 = base64_encode(&payload_bytes);
        let notif = make_notif(
            rpc_methods::DELIVER,
            json!({"from": "sender123", "payload": b64}),
        );
        let event = dispatch(&notif);
        match event {
            Some(BotEvent::PaymentRequest {
                session_id: sid,
                from,
                chain,
                amount,
                ..
            }) => {
                assert_eq!(sid, Uuid::nil().to_string());
                assert_eq!(from, "sender123");
                // Oracle: Chain::Zcash canonical lowercase wire form
                assert_eq!(chain, "zcash");
                assert_eq!(amount, "42");
            }
            other => panic!("expected PaymentRequest, got: {other:?}"),
        }
    }

    /// Oracle: a non-parseable payload (random bytes) must produce None, not an error.
    #[test]
    fn deliver_opaque_payload_returns_none() {
        let b64 = base64_encode(b"this is not valid json or ClearMessage");
        let notif = make_notif(rpc_methods::DELIVER, json!({"from": "xyz", "payload": b64}));
        let event = dispatch(&notif);
        assert!(
            event.is_none(),
            "opaque payload must yield None, got: {event:?}"
        );
    }

    /// Oracle: PaymentAction::Address is not a Request — must return None.
    #[test]
    fn deliver_payment_non_request_action_returns_none() {
        let session_id = Uuid::nil();
        let payload_bytes = serde_json::to_vec(&ClearMessage::Payment {
            session_id,
            action: PaymentAction::Address {
                chain: Chain::Zcash,
                address: "zs1abc".into(),
            },
        })
        .unwrap();
        let b64 = base64_encode(&payload_bytes);
        let notif = make_notif(rpc_methods::DELIVER, json!({"from": "p", "payload": b64}));
        assert!(dispatch(&notif).is_none());
    }

    // --- whisper_deliver ---

    /// Oracle: whisper_deliver with Chat payload must produce MessageReceived,
    /// same as deliver — both share dispatch_payload.
    #[test]
    fn whisper_deliver_chat_produces_message_received() {
        let payload_bytes = serde_json::to_vec(&ClearMessage::Chat {
            text: "whisper".into(),
        })
        .unwrap();
        let b64 = base64_encode(&payload_bytes);
        let notif = make_notif(
            rpc_methods::WHISPER_DELIVER,
            json!({"from": "whisperer", "payload": b64}),
        );
        let event = dispatch(&notif);
        match event {
            Some(BotEvent::MessageReceived { from, text, .. }) => {
                assert_eq!(from, "whisperer");
                assert_eq!(text, "whisper");
            }
            other => panic!("expected MessageReceived, got: {other:?}"),
        }
    }

    // --- user_joined / user_left ---

    /// Oracle: user_joined params produce BotEvent::UserJoined with correct fields.
    #[test]
    fn user_joined_with_nickname() {
        let notif = make_notif(
            rpc_methods::USER_JOINED,
            json!({"pub_id": "deadbeef", "nickname": "Alice", "sequence": 1}),
        );
        let event = dispatch(&notif);
        match event {
            Some(BotEvent::UserJoined {
                pub_id, nickname, ..
            }) => {
                assert_eq!(pub_id, "deadbeef");
                assert_eq!(nickname, Some("Alice".into()));
            }
            other => panic!("expected UserJoined, got: {other:?}"),
        }
    }

    /// Oracle: user_joined with no nickname field (or null) must produce UserJoined
    /// with nickname = None; the field must be absent in NDJSON output
    /// per #[serde(skip_serializing_if = "Option::is_none")] in BotEvent.
    #[test]
    fn user_joined_without_nickname() {
        let notif = make_notif(
            rpc_methods::USER_JOINED,
            json!({"pub_id": "cafebabe", "nickname": null, "sequence": 2}),
        );
        let event = dispatch(&notif);
        match event {
            Some(BotEvent::UserJoined {
                pub_id, nickname, ..
            }) => {
                assert_eq!(pub_id, "cafebabe");
                assert!(nickname.is_none());
            }
            other => panic!("expected UserJoined, got: {other:?}"),
        }
    }

    /// Oracle: user_left params produce BotEvent::UserLeft with correct pub_id.
    #[test]
    fn user_left_produces_event() {
        let notif = make_notif(rpc_methods::USER_LEFT, json!({"pub_id": "gone123"}));
        let event = dispatch(&notif);
        match event {
            Some(BotEvent::UserLeft { pub_id, .. }) => {
                assert_eq!(pub_id, "gone123");
            }
            other => panic!("expected UserLeft, got: {other:?}"),
        }
    }

    // --- directory_list and unknown methods ---

    /// Oracle: directory_list is handled by the caller — dispatch must return None.
    #[test]
    fn directory_list_returns_none() {
        let notif = make_notif(
            rpc_methods::DIRECTORY_LIST,
            json!({"online": [], "offline": []}),
        );
        assert!(dispatch(&notif).is_none());
    }

    /// Oracle: an entirely unknown method must silently return None.
    #[test]
    fn unknown_method_returns_none() {
        let notif = make_notif("some_future_method", json!({"data": 42}));
        assert!(dispatch(&notif).is_none());
    }

    /// Oracle: malformed params (wrong types) for a known method must return None,
    /// not panic or propagate an error.
    #[test]
    fn malformed_params_returns_none() {
        // user_joined expects pub_id: String but gets an integer
        let notif = make_notif(
            rpc_methods::USER_JOINED,
            json!({"pub_id": 12345, "sequence": "not_a_number"}),
        );
        assert!(dispatch(&notif).is_none());
    }

    /// Oracle: notification with no params field at all must return None gracefully.
    #[test]
    fn missing_params_returns_none() {
        let notif = JsonRpcNotification {
            version: "2.0".into(),
            method: rpc_methods::USER_LEFT.into(),
            params: None,
        };
        assert!(dispatch(&notif).is_none());
    }

    // --- Ack and Profile payloads ---

    /// Oracle: ClearMessage::Ack must return None — bots don't surface acks.
    #[test]
    fn deliver_ack_returns_none() {
        let payload_bytes = serde_json::to_vec(&ClearMessage::Ack {
            ref_id: Uuid::nil(),
        })
        .unwrap();
        let b64 = base64_encode(&payload_bytes);
        let notif = make_notif(rpc_methods::DELIVER, json!({"from": "x", "payload": b64}));
        assert!(dispatch(&notif).is_none());
    }

    /// Oracle: ClearMessage::Profile must return None — bots don't surface profile updates.
    #[test]
    fn deliver_profile_returns_none() {
        let payload_bytes = serde_json::to_vec(&ClearMessage::Profile {
            fields: std::collections::HashMap::new(),
        })
        .unwrap();
        let b64 = base64_encode(&payload_bytes);
        let notif = make_notif(rpc_methods::DELIVER, json!({"from": "x", "payload": b64}));
        assert!(dispatch(&notif).is_none());
    }

    // Helper: encode bytes as standard base64 (the same format serde_as Base64 uses)
    fn base64_encode(data: &[u8]) -> String {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode(data)
    }
}
