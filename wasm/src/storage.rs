use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use futures::channel::oneshot;
use std::cell::RefCell;
use std::rc::Rc;
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;
use web_sys::{IdbDatabase, IdbOpenDbRequest, IdbRequest, IdbTransactionMode};

/// Bridge an `IdbRequest` into an async `Result`.
///
/// The success/error closures capture the request by clone and send the
/// outcome through a oneshot channel.  Both closures are forgotten
/// (memory owned by JS until the event fires).
///
/// # Transaction abort handling
///
/// Per the IDB spec (§3.7.6.2), when a transaction is aborted (quota exceeded,
/// explicit `transaction.abort()`, or unhandled exception in a request handler),
/// all pending requests against that transaction receive an `error` event with
/// `DOMException.name == "AbortError"`.  The `onerror` closure above fires in
/// that case, so this function does *not* hang on transaction abort.
///
/// The one residual hang scenario is complete environment teardown (e.g. the
/// browser kills the worker before dispatching *any* event).  There is no
/// browser-portable way to detect this without a timeout; we accept it as a
/// known limitation.
///
/// `IdbRequest` does not have a `set_onabort` binding in web-sys; `onabort`
/// lives on `IdbDatabase` / `IdbTransaction`, not on individual requests.
async fn idb_request_result(request: IdbRequest) -> Result<JsValue, String> {
    let (tx, rx) = oneshot::channel::<Result<JsValue, String>>();
    let tx = Rc::new(RefCell::new(Some(tx)));

    let tx_ok = tx.clone();
    let req_ok = request.clone();
    let on_success = Closure::once(move |_: JsValue| {
        let result = req_ok.result().unwrap_or(JsValue::NULL);
        if let Some(sender) = tx_ok.borrow_mut().take() {
            let _ = sender.send(Ok(result));
        }
    });

    // `onerror` fires for both ordinary request failures and transaction
    // aborts (AbortError).  Extract the DOMException name where available so
    // callers see "idb request failed: AbortError" rather than a generic message.
    // We use JS reflection to read `event.target.error.name` without requiring
    // the `DomException` web-sys feature.
    let on_error = Closure::once(move |event: JsValue| {
        let reason = (|| -> Option<String> {
            let target = js_sys::Reflect::get(&event, &JsValue::from_str("target")).ok()?;
            let error = js_sys::Reflect::get(&target, &JsValue::from_str("error")).ok()?;
            let name = js_sys::Reflect::get(&error, &JsValue::from_str("name")).ok()?;
            name.as_string()
        })()
        .unwrap_or_else(|| "unknown".to_string());
        if let Some(sender) = tx.borrow_mut().take() {
            let _ = sender.send(Err(format!("idb request failed: {reason}")));
        }
    });

    request.set_onsuccess(Some(on_success.as_ref().unchecked_ref()));
    request.set_onerror(Some(on_error.as_ref().unchecked_ref()));
    on_success.forget();
    on_error.forget();

    rx.await.map_err(|_| "channel dropped".to_string())?
}

/// Open (or create) the `nie-identity` IndexedDB database at version 1.
///
/// If the database is new, `onupgradeneeded` creates the `"keys"` object store.
pub async fn open_db() -> Result<IdbDatabase, String> {
    let window = web_sys::window().ok_or("no window")?;
    let idb_factory = window
        .indexed_db()
        .map_err(|_| "indexeddb unavailable")?
        .ok_or("indexeddb not available (private browsing?)")?;

    let open_request = idb_factory
        .open_with_u32("nie-identity", 1)
        .map_err(|_| "failed to open db")?;

    let on_upgrade = Closure::once(move |event: web_sys::IdbVersionChangeEvent| {
        let db: IdbDatabase = event
            // unwrap_throw: IdbVersionChangeEvent always has a target
            .target()
            .unwrap_throw()
            // unwrap_throw: the target of an IDB open request is always IdbOpenDbRequest
            .dyn_into::<IdbOpenDbRequest>()
            .unwrap_throw()
            // unwrap_throw: we are inside onupgradeneeded, so the open request has succeeded and result is Some
            .result()
            .unwrap_throw()
            // unwrap_throw: the result of an IdbOpenDbRequest is always IdbDatabase
            .dyn_into::<IdbDatabase>()
            .unwrap_throw();
        // "keys" store doesn't exist yet — this is onupgradeneeded with a fresh DB
        let _ = db.create_object_store("keys");
    });
    open_request.set_onupgradeneeded(Some(on_upgrade.as_ref().unchecked_ref()));
    on_upgrade.forget();

    let result = idb_request_result(open_request.dyn_into::<IdbRequest>().unwrap_throw()).await?;
    result
        .dyn_into::<IdbDatabase>()
        .map_err(|_| "result is not an IdbDatabase".to_string())
}

/// Persist the 64-byte identity secret to IndexedDB.
///
/// Stored as `{"secret_b64": "<base64>"}` under the key `"default"`.
/// The base64 string is never logged.
pub async fn save_identity(secret_bytes: &[u8; 64]) -> Result<(), String> {
    let db = open_db().await?;

    let tx = db
        .transaction_with_str_and_mode("keys", IdbTransactionMode::Readwrite)
        .map_err(|_| "failed to start readwrite transaction")?;
    let store = tx.object_store("keys").map_err(|_| "no keys store")?;

    // Never log secret_b64 — it contains raw key material.
    let secret_b64 = B64.encode(secret_bytes);
    let json = serde_json::json!({"secret_b64": secret_b64}).to_string();
    let js_value = JsValue::from_str(&json);

    let request = store
        .put_with_key(&js_value, &JsValue::from_str("default"))
        .map_err(|_| "put failed")?;

    idb_request_result(request).await?;
    Ok(())
}

/// Load the 64-byte identity secret from IndexedDB.
///
/// Returns `None` if no identity has been stored yet.
pub async fn load_identity() -> Result<Option<[u8; 64]>, String> {
    let db = open_db().await?;

    let tx = db
        .transaction_with_str("keys")
        .map_err(|_| "failed to start readonly transaction")?;
    let store = tx.object_store("keys").map_err(|_| "no keys store")?;

    let request = store
        .get(&JsValue::from_str("default"))
        .map_err(|_| "get failed")?;

    let result = idb_request_result(request).await?;

    if result.is_null() || result.is_undefined() {
        return Ok(None);
    }

    let json_str = result.as_string().ok_or("result is not a string")?;
    let parsed: serde_json::Value =
        serde_json::from_str(&json_str).map_err(|e| format!("parse error: {e}"))?;

    let secret_b64 = parsed["secret_b64"]
        .as_str()
        .ok_or("missing secret_b64 field")?;

    // Never log secret_b64 — it contains raw key material.
    let bytes = B64
        .decode(secret_b64)
        .map_err(|e| format!("base64 decode error: {e}"))?;

    let arr: [u8; 64] = bytes
        .try_into()
        .map_err(|_| "keyfile corrupt: expected 64 bytes".to_string())?;

    Ok(Some(arr))
}
