use chrono::{DateTime, Utc};
use nie_core::messages::PaymentSession;
use zeroize::Zeroizing;
use nie_core::mls::MlsClient;
use nie_wallet::db::WalletStore;
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};
use uuid::Uuid;

/// A single line in the chat history
#[derive(Debug, Clone)]
pub enum ChatLine {
    Chat {
        from: String,
        text: String,
        ts: DateTime<Utc>,
    },
    System(String),
}

/// Keyboard focus target
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Focus {
    Input,
    UserList,
}

/// Relay connection state
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectionState {
    Connecting,
    Connected,
    Reconnecting { delay_secs: u64 },
    Offline,
}

impl std::fmt::Display for ConnectionState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Connecting => write!(f, "connecting"),
            Self::Connected => write!(f, "connected"),
            Self::Reconnecting { delay_secs } => write!(f, "reconnecting in {delay_secs}s"),
            Self::Offline => write!(f, "offline"),
        }
    }
}

/// A timed overlay notification (payment events, etc.)
#[derive(Debug, Clone)]
pub struct PaymentOverlay {
    pub text: String,
    pub created_at: Instant,
    pub dismiss_after: Duration,
}

impl PaymentOverlay {
    pub fn new(text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            created_at: Instant::now(),
            dismiss_after: Duration::from_secs(8),
        }
    }

    pub fn is_expired(&self) -> bool {
        self.created_at.elapsed() >= self.dismiss_after
    }
}

/// Info about an online user (mirrors nie_core::protocol::UserInfo)
#[derive(Debug, Clone)]
pub struct OnlineUser {
    pub pub_id: String,
    pub nickname: Option<String>,
    pub sequence: u64,
}

/// All mutable runtime state for the TUI
pub struct AppState {
    /// Own pub_id (set at startup, immutable after)
    pub my_pub_id: String,
    /// Online users sorted ascending by sequence (online[0] = MLS admin)
    /// INVARIANT: Never sort this Vec in place — only rebuild from DirectoryList or
    /// insert at partition_point to maintain ascending sequence order.
    pub online: Vec<OnlineUser>,
    /// Server-assigned nicknames cache: pub_id → nickname
    pub nicknames: HashMap<String, String>,
    /// Local contact aliases: pub_id → local name
    pub local_names: HashMap<String, String>,
    /// Chat message ring buffer (capped at MAX_MESSAGES)
    pub messages: VecDeque<ChatLine>,
    /// Lines from bottom (0 = show latest)
    pub scroll_offset: usize,
    /// Current input buffer
    pub input: String,
    /// Byte offset of cursor in input (must always be on a UTF-8 char boundary)
    pub input_cursor: usize,
    /// Keyboard focus
    pub focus: Focus,
    /// Relay connection state
    pub connection: ConnectionState,
    /// Whether MLS group is established
    pub mls_active: bool,
    /// Ephemeral MLS client (reset on reconnect)
    pub mls_client: MlsClient,
    /// Own X25519 HPKE identity secret (for sealed messages when MLS inactive)
    /// KEY MATERIAL — never log, never debug-print
    pub hpke_identity_secret: [u8; 32],
    /// Own X25519 HPKE identity public key (safe to publish)
    pub hpke_identity_pub: [u8; 32],
    /// MLS-derived room HPKE secret (when MLS active)
    /// KEY MATERIAL — never log
    pub room_hpke_secret: Option<Zeroizing<[u8; 32]>>,
    /// Timed payment overlay notifications
    pub payment_overlays: VecDeque<PaymentOverlay>,
    /// In-flight payment sessions: session_id → session
    pub sessions: HashMap<Uuid, PaymentSession>,
    /// Own profile fields
    pub own_profile: HashMap<String, String>,
    /// True after first DirectoryList received
    pub ever_connected: bool,
    /// Terminal size (width, height) in cells
    pub terminal_size: (u16, u16),
    /// Set to true to exit the event loop
    pub quit: bool,
    /// Wallet store — None if wallet.db absent or failed to open.
    /// KEY MATERIAL — never log, never debug-print
    pub wallet: Option<Arc<WalletStore>>,
}

const MAX_MESSAGES: usize = 5000;

impl AppState {
    pub fn new(
        my_pub_id: String,
        hpke_identity_secret: [u8; 32],
        hpke_identity_pub: [u8; 32],
        mls_client: MlsClient,
    ) -> Self {
        Self {
            my_pub_id,
            online: Vec::new(),
            nicknames: HashMap::new(),
            local_names: HashMap::new(),
            messages: VecDeque::new(),
            scroll_offset: 0,
            input: String::new(),
            input_cursor: 0,
            focus: Focus::Input,
            connection: ConnectionState::Connecting,
            mls_active: false,
            mls_client,
            hpke_identity_secret,
            hpke_identity_pub,
            room_hpke_secret: None,
            payment_overlays: VecDeque::new(),
            sessions: HashMap::new(),
            own_profile: HashMap::new(),
            ever_connected: false,
            terminal_size: (80, 24),
            quit: false,
            wallet: None,
        }
    }

    /// Push a chat line, maintaining the MAX_MESSAGES cap.
    pub fn push_message(&mut self, line: ChatLine) {
        if self.messages.len() >= MAX_MESSAGES {
            self.messages.pop_front();
        }
        self.messages.push_back(line);
    }

    /// Push a payment overlay notification.
    pub fn push_overlay(&mut self, text: impl Into<String>) {
        self.payment_overlays.push_back(PaymentOverlay::new(text));
    }

    /// Remove expired overlays. Call on each render tick.
    pub fn prune_overlays(&mut self) {
        while self
            .payment_overlays
            .front()
            .is_some_and(|o| o.is_expired())
        {
            self.payment_overlays.pop_front();
        }
    }

    /// Active overlay text (first non-expired overlay), if any.
    pub fn active_overlay(&self) -> Option<&str> {
        self.payment_overlays
            .iter()
            .find(|o| !o.is_expired())
            .map(|o| o.text.as_str())
    }

    /// Resolve display name for a pub_id.
    /// Precedence: server nickname > local alias > first 8 chars of pub_id + "…"
    pub fn display_name(&self, pub_id: &str) -> String {
        if let Some(nick) = self.nicknames.get(pub_id) {
            return nick.clone();
        }
        if let Some(alias) = self.local_names.get(pub_id) {
            return alias.clone();
        }
        // Short form: first 8 chars + ellipsis
        if pub_id.len() > 8 {
            format!("{}…", &pub_id[..8])
        } else {
            pub_id.to_string()
        }
    }

    /// Clamp scroll_offset to not exceed the draw ceiling used by draw_chat.
    /// draw_chat caps scroll at messages.len().saturating_sub(inner_height) where
    /// inner_height = terminal_size.1.saturating_sub(6). Match that ceiling here
    /// so PageUp cannot set an offset that draw_chat silently reduces further.
    pub fn clamp_scroll(&mut self) {
        let visible = self.terminal_size.1.saturating_sub(6) as usize;
        let max_scroll = self.messages.len().saturating_sub(visible);
        if self.scroll_offset > max_scroll {
            self.scroll_offset = max_scroll;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_state() -> AppState {
        let mls = nie_core::mls::MlsClient::new(
            "test_pub_id_0000000000000000000000000000000000000000000000000000000000000000",
        )
        .unwrap();
        AppState::new(
            "test_pub_id_0000000000000000000000000000000000000000000000000000000000000000"
                .to_string(),
            [0u8; 32],
            [0u8; 32],
            mls,
        )
    }

    #[test]
    fn push_message_cap() {
        let mut state = make_state();
        for i in 0..5001 {
            state.push_message(ChatLine::System(format!("msg {i}")));
        }
        assert_eq!(state.messages.len(), 5000);
        // First message should be "msg 1" (msg 0 was evicted)
        assert!(matches!(&state.messages[0], ChatLine::System(s) if s == "msg 1"));
    }

    #[test]
    fn display_name_precedence() {
        let mut state = make_state();
        let pub_id = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";
        // No entries: should return short form
        assert_eq!(state.display_name(pub_id), "abcdef12…");
        // Local alias takes precedence over short form
        state
            .local_names
            .insert(pub_id.to_string(), "alice".to_string());
        assert_eq!(state.display_name(pub_id), "alice");
        // Server nickname takes precedence over local alias
        state
            .nicknames
            .insert(pub_id.to_string(), "Alice (verified)".to_string());
        assert_eq!(state.display_name(pub_id), "Alice (verified)");
    }

    #[test]
    fn overlay_expiry() {
        let overlay = PaymentOverlay {
            text: "test".to_string(),
            created_at: Instant::now() - Duration::from_secs(10),
            dismiss_after: Duration::from_secs(8),
        };
        assert!(overlay.is_expired());

        let overlay_fresh = PaymentOverlay::new("fresh");
        assert!(!overlay_fresh.is_expired());
    }

    #[test]
    fn prune_overlays_removes_expired() {
        let mut state = make_state();
        state.payment_overlays.push_back(PaymentOverlay {
            text: "old".to_string(),
            created_at: Instant::now() - Duration::from_secs(10),
            dismiss_after: Duration::from_secs(8),
        });
        state.push_overlay("fresh");
        state.prune_overlays();
        assert_eq!(state.payment_overlays.len(), 1);
        assert_eq!(state.payment_overlays[0].text, "fresh");
    }
}
