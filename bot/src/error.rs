use thiserror::Error;

#[derive(Debug, Error)]
pub enum BotError {
    #[error("config error: {0}")]
    Config(String),

    #[error("keyfile error: {0}")]
    Keyfile(String),

    #[error("relay connection error: {0}")]
    RelayConnect(String),

    #[error("stdin closed (clean exit)")]
    StdinClosed,

    #[error("script timeout: {path} did not exit within {secs}s")]
    ScriptTimeout { path: String, secs: u64 },

    #[error("script failed with exit code {exit_code}")]
    ScriptFailed { exit_code: i32 },

    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
}
