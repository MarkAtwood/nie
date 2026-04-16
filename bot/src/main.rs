use anyhow::Result;
use clap::Parser;
use nie_core::identity::Identity;
use nie_core::messages::ClearMessage;
use nie_core::protocol::{rpc_methods, BroadcastParams, JsonRpcRequest, SetNicknameParams};
use nie_core::transport::{next_request_id, ClientEvent};
use tokio::sync::mpsc;
use tracing_subscriber::EnvFilter;

mod config;
pub mod dispatcher;
mod error;
mod io_types;
pub mod payment;
pub mod scripting;
pub mod stdin_reader;
pub use config::{resolve, BotConfig, ResolvedBotConfig};
pub use dispatcher::dispatch;
pub use error::BotError;
pub use io_types::{BotCommand, BotEvent};

#[derive(Parser)]
#[command(name = "nie-bot", about = "automated nie relay bot")]
struct Cli {
    /// Relay WebSocket URL.
    #[arg(long)]
    relay: Option<String>,

    /// Path to identity keyfile.
    #[arg(long)]
    keyfile: Option<String>,

    /// Override the nie data directory.
    #[arg(long)]
    data_dir: Option<String>,

    /// SOCKS5 proxy URL (e.g. socks5h://127.0.0.1:9050 for Tor).
    #[arg(long, value_name = "URL")]
    proxy: Option<String>,

    /// Shell command to invoke on each received message.
    #[arg(long, value_name = "CMD")]
    on_message_hook: Option<String>,

    /// Automatically respond with a payment address when requested.
    #[arg(long)]
    auto_payment_address: bool,

    /// Run a self-test and exit.
    #[arg(long)]
    self_test: bool,

    /// Skip TLS certificate verification. Dev only — never use in production.
    #[arg(long, hide = true)]
    insecure: bool,

    /// Skip passphrase protection. Testing and CI only — identity key will NOT be encrypted.
    #[arg(long, hide = true)]
    no_passphrase: bool,

    /// Log level (e.g. debug, info, warn, error).
    #[arg(long)]
    log_level: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Config dir: XDG_CONFIG_HOME/nie or ~/.config/nie
    let config_dir = dirs::config_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join("nie");

    let file_config = BotConfig::load(&config_dir)?;

    let config = resolve(
        cli.relay,
        cli.keyfile,
        cli.data_dir,
        cli.proxy,
        cli.on_message_hook,
        cli.auto_payment_address,
        cli.self_test,
        cli.insecure,
        cli.no_passphrase,
        cli.log_level,
        file_config,
    )?;

    // try_init to avoid panic if tracing is already initialized (e.g. in tests)
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::new(&config.log_level))
        .try_init()
        .ok();

    let keyfile_path = config.keyfile.to_string_lossy().into_owned();
    let identity = nie_core::keyfile::load_identity(&keyfile_path, config.no_passphrase)?;

    if config.self_test {
        return run_self_test(config.relay, identity, config.insecure, config.proxy).await;
    }
    let my_pub_id = identity.pub_id().0.clone();

    // connect_with_retry is synchronous — spawns a background reconnect task internally
    let mut conn = nie_core::transport::connect_with_retry(
        config.relay.clone(),
        identity,
        config.insecure,
        config.proxy.clone(),
    );

    BotEvent::connected(config.relay.clone(), my_pub_id.clone()).emit()?;

    let (cmd_tx, mut cmd_rx) = mpsc::channel::<BotCommand>(32);
    let (event_tx, mut event_rx) = mpsc::channel::<BotEvent>(32);

    tokio::spawn(stdin_reader::run(cmd_tx, event_tx.clone()));

    let conn_tx = conn.tx.clone();

    loop {
        tokio::select! {
            Some(client_event) = conn.rx.recv() => {
                handle_relay_event(client_event, &conn_tx, &config, &my_pub_id).await;
            }
            Some(cmd) = cmd_rx.recv() => {
                handle_command(cmd, &conn_tx, &my_pub_id).await.ok();
            }
            Some(ev) = event_rx.recv() => {
                ev.emit().ok();
            }
            else => break,
        }
    }

    BotEvent::disconnected("shutdown").emit().ok();
    Ok(())
}

async fn handle_relay_event(
    client_event: ClientEvent,
    conn_tx: &mpsc::Sender<JsonRpcRequest>,
    config: &ResolvedBotConfig,
    my_pub_id: &str,
) {
    let _ = conn_tx; // reserved for future use (e.g. auto-reply)
    match client_event {
        ClientEvent::Message(notif) => {
            // directory_list produces no user-visible event; short-circuit explicitly
            if notif.method == rpc_methods::DIRECTORY_LIST {
                return;
            }

            if let Some(ev) = dispatch(&notif) {
                // Emit the relay event before running the hook so consumers see the
                // message before the script output it triggers.
                ev.emit().ok();
                if let (Some(hook), BotEvent::MessageReceived { from, text, .. }) =
                    (&config.on_message_hook, &ev)
                {
                    let env_vars = [("NIE_FROM", from.as_str()), ("NIE_TEXT", text.as_str())];
                    match scripting::run_hook(hook, &env_vars).await {
                        Ok(r) => {
                            BotEvent::ScriptOutput {
                                command: hook.clone(),
                                exit_code: r.exit_code,
                                stdout: r.stdout,
                                stderr: r.stderr,
                                ts: chrono::Utc::now().to_rfc3339(),
                            }
                            .emit()
                            .ok();
                        }
                        Err(e) => {
                            BotEvent::error(format!("hook failed: {e}")).emit().ok();
                        }
                    }
                }
            }
        }
        ClientEvent::Reconnecting { delay_secs } => {
            BotEvent::Reconnecting {
                delay_secs,
                ts: chrono::Utc::now().to_rfc3339(),
            }
            .emit()
            .ok();
        }
        ClientEvent::Reconnected => {
            BotEvent::Connected {
                relay_url: config.relay.clone(),
                pub_id: my_pub_id.to_string(),
                ts: chrono::Utc::now().to_rfc3339(),
            }
            .emit()
            .ok();
        }
        ClientEvent::Response(_) => {
            // Request ID tracking not done in Phase 4f
            tracing::trace!("relay response received (ignored in Phase 4f)");
        }
    }
}

async fn handle_command(
    cmd: BotCommand,
    conn_tx: &mpsc::Sender<JsonRpcRequest>,
    my_pub_id: &str,
) -> anyhow::Result<()> {
    match cmd {
        BotCommand::Send { text } => {
            let msg = ClearMessage::Chat { text };
            // derived Serialize, infallible
            let payload = serde_json::to_vec(&msg).unwrap();
            let req = JsonRpcRequest::new(
                next_request_id(),
                rpc_methods::BROADCAST,
                BroadcastParams { payload },
            )?;
            conn_tx.send(req).await.ok(); // ignore if channel closed
        }
        BotCommand::SetNickname { nickname } => {
            let req = JsonRpcRequest::new(
                next_request_id(),
                rpc_methods::SET_NICKNAME,
                SetNicknameParams { nickname },
            )?;
            conn_tx.send(req).await.ok();
        }
        BotCommand::Whoami => {
            BotEvent::connected(String::new(), my_pub_id.to_string())
                .emit()
                .ok();
        }
        BotCommand::Users => {
            // Directory not tracked in Phase 4f
        }
        BotCommand::Quit => std::process::exit(0),
    }
    Ok(())
}

async fn run_self_test(
    relay_url: String,
    identity: Identity,
    insecure: bool,
    proxy: Option<String>,
) -> Result<()> {
    use nie_core::protocol::{WhisperDeliverParams, WhisperParams};
    use nie_core::transport::connect_with_retry;
    use tokio::time::{timeout, Duration};

    let my_pub_id = identity.pub_id().0.clone();
    let mut conn = connect_with_retry(relay_url, identity, insecure, proxy);

    const SENTINEL: &str = "__nie_bot_self_test__";
    // derived Serialize, infallible
    let payload = serde_json::to_vec(&ClearMessage::Chat {
        text: SENTINEL.into(),
    })
    .unwrap();

    let req = JsonRpcRequest::new(
        next_request_id(),
        rpc_methods::WHISPER,
        WhisperParams {
            to: my_pub_id.clone(),
            payload,
        },
    )?;

    let result = timeout(Duration::from_secs(10), async {
        let mut sent = false;
        let conn_tx = conn.tx.clone();
        loop {
            match conn.rx.recv().await {
                Some(ClientEvent::Message(notif)) => {
                    if notif.method == rpc_methods::DIRECTORY_LIST && !sent {
                        conn_tx.send(req.clone()).await.ok();
                        sent = true;
                    }
                    if notif.method == rpc_methods::WHISPER_DELIVER && sent {
                        let raw = notif
                            .params
                            .ok_or_else(|| anyhow::anyhow!("whisper_deliver missing params"))?;
                        let params: WhisperDeliverParams = serde_json::from_value(raw)?;
                        let msg: ClearMessage = serde_json::from_slice(&params.payload)?;
                        if let ClearMessage::Chat { text } = msg {
                            if text == SENTINEL {
                                return Ok::<(), anyhow::Error>(());
                            }
                        }
                    }
                }
                Some(ClientEvent::Reconnecting { .. })
                | Some(ClientEvent::Reconnected)
                | Some(ClientEvent::Response(_)) => {}
                None => anyhow::bail!("relay connection closed before self-test completed"),
            }
        }
    })
    .await;

    match result {
        Ok(Ok(())) => {
            println!("PASS");
            Ok(())
        }
        Ok(Err(e)) => {
            eprintln!("FAIL: {e}");
            std::process::exit(1);
        }
        Err(_) => {
            eprintln!("FAIL: self-test timed out after 10s");
            std::process::exit(1);
        }
    }
}
