pub mod auth;
pub mod hpke;
pub mod identity;
// keyfile uses std::fs and rpassword — not available in wasm32
#[cfg(not(target_arch = "wasm32"))]
pub mod keyfile;
pub mod messages;
// mls uses openmls/openmls_rust_crypto — not available in wasm32
#[cfg(not(target_arch = "wasm32"))]
pub mod mls;
pub mod protocol;
// transport uses tokio-tungstenite and tokio runtime — not available in wasm32
#[cfg(not(target_arch = "wasm32"))]
pub mod transport;
pub mod wallet;

pub use identity::{Identity, PubId};
pub use messages::{Chain, ClearMessage, PaymentAction, PaymentRole, PaymentSession, PaymentState};
