use wasm_bindgen::prelude::*;

pub mod api;
pub mod client;
pub mod storage;
pub mod transport;

pub use api::{generate_identity, load_identity, pub_id_from_secret, save_identity, NieClient};

/// Initialize the WASM module. Call this once before using any other function.
/// Sets up panic messages to appear in the browser console.
#[wasm_bindgen(start)]
pub fn init() {
    console_error_panic_hook::set_once();
}
