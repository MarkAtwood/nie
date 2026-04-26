use anyhow::Result;
use nie_core::messages::{Chain, ClearMessage, PaymentAction};
use nie_core::protocol::{rpc_methods, JsonRpcRequest, WhisperParams};
use nie_core::transport::next_request_id;
use tokio::sync::mpsc;

use crate::io_types::BotEvent;

/// If `auto_payment_address` is enabled and `event` is a `PaymentRequest`,
/// sends a stub `PaymentAction::Address` whisper back to the requester.
///
/// # PHASE 4F STUB
///
/// The address returned is NOT a real Zcash/Monero/MobileCoin address.
/// Real wallet integration is Phase 2+. The stub address is derived from the
/// session_id solely to make it unique per session; it provides no
/// privacy or unlinkability guarantee whatsoever.
pub async fn maybe_auto_respond(
    event: &BotEvent,
    auto_payment_address: bool,
    relay_tx: &mpsc::Sender<JsonRpcRequest>,
) -> Result<()> {
    if !auto_payment_address {
        return Ok(());
    }

    let (session_id_str, from, chain_str) = match event {
        BotEvent::PaymentRequest {
            session_id,
            from,
            chain,
            ..
        } => (session_id.as_str(), from.as_str(), chain.as_str()),
        _ => return Ok(()), // not a payment request — nothing to do
    };

    // Parse the chain string (serde lowercase form: "zcash", "monero", "mobilecoin").
    let chain = match chain_str {
        "zcash" => Chain::Zcash,
        "monero" => Chain::Monero,
        "mobilecoin" => Chain::Mobilecoin,
        _ => {
            tracing::warn!("unknown chain in payment request: {chain_str}");
            return Ok(());
        }
    };

    // Parse session_id to Uuid; return descriptive error on malformed input.
    let session_id = session_id_str
        .parse::<uuid::Uuid>()
        .map_err(|e| anyhow::anyhow!("bad session_id in PaymentRequest: {e}"))?;

    // PHASE 4F STUB: not a real Zcash/Monero/MobileCoin address.
    // session_id makes it unique per request; real wallet generates a fresh
    // subaddress here (Phase 2, nie-neg).
    let stub_address = format!("STUB_TESTNET_ADDRESS_{session_id}");

    let reply = ClearMessage::Payment {
        session_id,
        action: PaymentAction::Address {
            chain,
            address: stub_address,
        },
    };

    // serde_json::to_vec on a derived Serialize cannot fail
    let payload = serde_json::to_vec(&reply).unwrap();

    let req = JsonRpcRequest::new(
        next_request_id(),
        rpc_methods::WHISPER,
        WhisperParams {
            to: from.to_owned(),
            payload,
        },
    )
    .map_err(|e| anyhow::anyhow!("failed to build whisper request: {e}"))?;

    // Channel close is a clean shutdown — treat send failure as Ok.
    relay_tx.send(req).await.ok();

    // Log only the pub_id prefix — never the full id (64 chars), never session_id.
    let prefix_len = 8.min(from.len());
    tracing::warn!(
        "sent STUB payment address to {} — real wallet integration required before production use",
        &from[..prefix_len]
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_payment_request(session_id: &str, chain: &str) -> BotEvent {
        BotEvent::PaymentRequest {
            session_id: session_id.to_owned(),
            from: "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890".to_owned(),
            chain: chain.to_owned(),
            amount: "100000".to_owned(),
            ts: "2026-01-01T00:00:00+00:00".to_owned(),
        }
    }

    /// When auto_payment_address is false, nothing is sent regardless of event type.
    #[tokio::test]
    async fn test_auto_respond_disabled() {
        let (tx, mut rx) = mpsc::channel::<JsonRpcRequest>(4);
        let event = make_payment_request("550e8400-e29b-41d4-a716-446655440000", "zcash");

        let result = maybe_auto_respond(&event, false, &tx).await;
        assert!(result.is_ok(), "expected Ok, got: {:?}", result.err());

        // Nothing should have been sent on the channel.
        assert!(
            rx.try_recv().is_err(),
            "expected no message when auto_payment_address=false"
        );
    }

    /// A non-payment event is a no-op even when auto_payment_address is true.
    #[tokio::test]
    async fn test_auto_respond_non_payment_event() {
        let (tx, mut rx) = mpsc::channel::<JsonRpcRequest>(4);
        let event = BotEvent::Error {
            reason: "something went wrong".to_owned(),
            ts: "2026-01-01T00:00:00+00:00".to_owned(),
        };

        let result = maybe_auto_respond(&event, true, &tx).await;
        assert!(result.is_ok(), "expected Ok, got: {:?}", result.err());

        assert!(
            rx.try_recv().is_err(),
            "expected no message for non-PaymentRequest event"
        );
    }

    /// A well-formed PaymentRequest with auto_payment_address=true sends a whisper.
    #[tokio::test]
    async fn test_auto_respond_sends_whisper() {
        let (tx, mut rx) = mpsc::channel::<JsonRpcRequest>(4);
        let event = make_payment_request("550e8400-e29b-41d4-a716-446655440000", "zcash");

        let result = maybe_auto_respond(&event, true, &tx).await;
        assert!(result.is_ok(), "expected Ok, got: {:?}", result.err());

        let req = rx
            .try_recv()
            .expect("expected a JsonRpcRequest to be sent on the channel");
        assert_eq!(req.method, rpc_methods::WHISPER, "expected whisper method");
    }

    /// A malformed session_id (not a valid UUID) returns Err with context.
    #[tokio::test]
    async fn test_auto_respond_bad_session_id_returns_err() {
        let (tx, _rx) = mpsc::channel::<JsonRpcRequest>(4);
        let event = make_payment_request("not-a-uuid", "zcash");

        let result = maybe_auto_respond(&event, true, &tx).await;
        assert!(
            result.is_err(),
            "expected Err for malformed session_id, got Ok"
        );
        let err_msg = format!("{}", result.unwrap_err());
        assert!(
            err_msg.contains("bad session_id"),
            "error message should mention bad session_id, got: {err_msg}"
        );
    }

    /// An unknown chain string logs a warning and returns Ok (no send).
    #[tokio::test]
    async fn test_auto_respond_unknown_chain_is_noop() {
        let (tx, mut rx) = mpsc::channel::<JsonRpcRequest>(4);
        let event = make_payment_request("550e8400-e29b-41d4-a716-446655440000", "dogecoin");

        let result = maybe_auto_respond(&event, true, &tx).await;
        assert!(result.is_ok(), "expected Ok, got: {:?}", result.err());

        assert!(
            rx.try_recv().is_err(),
            "expected no message for unknown chain"
        );
    }
}
