use anyhow::Result;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::sync::mpsc;

use crate::io_types::{BotCommand, BotEvent};

/// Run the stdin reader loop.
///
/// Reads JSON-encoded BotCommands from stdin, one per line.
/// - EOF: sends nothing, returns Ok(()) — caller treats channel close as shutdown signal.
/// - Malformed JSON: sends BotEvent::Error to event_tx and continues reading.
/// - Valid command: sends to cmd_tx.
/// - Either channel closed (receiver dropped): returns Ok(()) silently.
pub async fn run(cmd_tx: mpsc::Sender<BotCommand>, event_tx: mpsc::Sender<BotEvent>) -> Result<()> {
    let stdin = tokio::io::stdin();
    let mut reader = BufReader::new(stdin);
    let mut line = String::new();

    loop {
        line.clear();
        let n = reader.read_line(&mut line).await?;

        // EOF
        if n == 0 {
            return Ok(());
        }

        let trimmed = line.trim();
        if trimmed.is_empty() {
            tracing::trace!("stdin: blank line skipped");
            continue;
        }

        match serde_json::from_str::<BotCommand>(trimmed) {
            Ok(cmd) => {
                if cmd_tx.send(cmd).await.is_err() {
                    return Ok(()); // main loop gone
                }
            }
            Err(e) => {
                let ev = BotEvent::error(format!("stdin parse error: {e}"));
                // best-effort: if event channel is gone, stop reading
                if event_tx.send(ev).await.is_err() {
                    return Ok(());
                }
            }
        }
    }
}
