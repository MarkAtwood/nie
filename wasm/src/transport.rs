use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::rc::Rc;

use futures::channel::oneshot;
use serde_json::Value;
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;
use web_sys::{CloseEvent, ErrorEvent, MessageEvent, WebSocket};

/// Shared map from in-flight request id to the oneshot that resolves it.
type PendingMap = Rc<RefCell<HashMap<u64, oneshot::Sender<Result<Value, String>>>>>;

/// Shared Rust callback for incoming JSON-RPC notifications.
type NotifyCb = Rc<RefCell<Option<Box<dyn FnMut(Value)>>>>;

pub struct WasmTransport {
    ws: WebSocket,
    next_id: Rc<Cell<u64>>,
    pending: PendingMap,
    notify_cb: NotifyCb,
    // Stored to keep closures alive; dropping a Closure removes the JS handler.
    _onopen: Closure<dyn FnMut(JsValue)>,
    _onmessage: Closure<dyn FnMut(MessageEvent)>,
    _onerror: Closure<dyn FnMut(ErrorEvent)>,
    _onclose: Closure<dyn FnMut(CloseEvent)>,
}

impl WasmTransport {
    /// Open a WebSocket connection to `url`.
    ///
    /// Returns `(WasmTransport, open_rx)`. Await `open_rx` before calling
    /// `send_request` — it resolves `Ok(())` when the connection is open, or
    /// `Err(String)` if the open fails (the error closure fires instead).
    pub fn connect(
        url: &str,
    ) -> Result<(WasmTransport, oneshot::Receiver<Result<(), String>>), String> {
        let ws = WebSocket::new(url).map_err(|e| format!("WS error: {:?}", e))?;

        let next_id: Rc<Cell<u64>> = Rc::new(Cell::new(1));
        let pending: PendingMap = Rc::new(RefCell::new(HashMap::new()));
        let notify_cb: NotifyCb = Rc::new(RefCell::new(None));

        // oneshot for "connection is open"
        let (open_tx, open_rx) = oneshot::channel::<Result<(), String>>();
        // Type alias scoped to this function to satisfy clippy::type_complexity
        type OpenCell = Rc<RefCell<Option<oneshot::Sender<Result<(), String>>>>>;
        let open_tx_cell: OpenCell = Rc::new(RefCell::new(Some(open_tx)));

        // --- onopen ---
        let open_tx_clone = Rc::clone(&open_tx_cell);
        let onopen = Closure::<dyn FnMut(JsValue)>::new(move |_event: JsValue| {
            if let Some(tx) = open_tx_clone.borrow_mut().take() {
                // Ignore send error — caller already dropped the receiver.
                let _ = tx.send(Ok(()));
            }
        });
        ws.set_onopen(Some(onopen.as_ref().unchecked_ref()));

        // --- onmessage ---
        let pending_msg = Rc::clone(&pending);
        let notify_cb_msg = Rc::clone(&notify_cb);
        let onmessage = Closure::<dyn FnMut(MessageEvent)>::new(move |event: MessageEvent| {
            let text = match event.data().as_string() {
                Some(t) => t,
                None => {
                    web_sys::console::warn_1(&JsValue::from_str(
                        "nie-wasm: received non-text WebSocket frame, ignoring",
                    ));
                    return;
                }
            };

            let value: Value = match serde_json::from_str(&text) {
                Ok(v) => v,
                Err(_) => {
                    web_sys::console::warn_1(&JsValue::from_str(
                        "nie-wasm: received non-JSON WebSocket message, ignoring",
                    ));
                    return;
                }
            };

            // Per JSON-RPC 2.0: a notification has no "id" key at all; a response
            // has an "id" key (which may be null for error responses where the id
            // could not be determined).
            let has_id = value.get("id").is_some();
            let has_result = value.get("result").is_some();
            let has_error = value.get("error").is_some();
            let has_method = value.get("method").is_some();

            if has_id && (has_result || has_error) {
                // JSON-RPC response
                let id = match value["id"].as_u64() {
                    Some(id) => id,
                    None => {
                        web_sys::console::warn_1(&JsValue::from_str(
                            "nie-wasm: JSON-RPC response has non-integer id, ignoring",
                        ));
                        return;
                    }
                };

                let sender = pending_msg.borrow_mut().remove(&id);
                if let Some(tx) = sender {
                    let outcome = if has_error {
                        let msg = value["error"]["message"]
                            .as_str()
                            .unwrap_or("unknown error")
                            .to_string();
                        Err(msg)
                    } else {
                        Ok(value["result"].clone())
                    };
                    // Ignore send error — caller already dropped the receiver.
                    let _ = tx.send(outcome);
                }
            } else if has_method && !has_id {
                // JSON-RPC notification — call the Rust callback directly with
                // the already-parsed value; no second JSON parse needed.
                if let Some(f) = notify_cb_msg.borrow_mut().as_mut() {
                    f(value);
                }
            }
        });
        ws.set_onmessage(Some(onmessage.as_ref().unchecked_ref()));

        // --- onerror ---
        let open_tx_error = Rc::clone(&open_tx_cell);
        let onerror = Closure::<dyn FnMut(ErrorEvent)>::new(move |_event: ErrorEvent| {
            web_sys::console::error_1(&JsValue::from_str("nie-wasm: WebSocket error"));
            // Resolve the open_rx with an error so callers don't hang forever.
            if let Some(tx) = open_tx_error.borrow_mut().take() {
                // Ignore send error — caller already dropped the receiver.
                let _ = tx.send(Err("WebSocket error".to_string()));
            }
        });
        ws.set_onerror(Some(onerror.as_ref().unchecked_ref()));

        // --- onclose ---
        let pending_close = Rc::clone(&pending);
        let open_tx_close = Rc::clone(&open_tx_cell);
        let onclose = Closure::<dyn FnMut(CloseEvent)>::new(move |_event: CloseEvent| {
            web_sys::console::warn_1(&JsValue::from_str("nie-wasm: WebSocket closed"));
            // If open_rx has not yet been resolved (close during handshake), resolve it now.
            if let Some(tx) = open_tx_close.borrow_mut().take() {
                // Ignore send error — caller already dropped the receiver.
                let _ = tx.send(Err("disconnected".to_string()));
            }
            // Reject all in-flight requests.
            let mut map = pending_close.borrow_mut();
            for (_, tx) in map.drain() {
                let _ = tx.send(Err("disconnected".to_string()));
            }
        });
        ws.set_onclose(Some(onclose.as_ref().unchecked_ref()));

        let transport = WasmTransport {
            ws,
            next_id,
            pending,
            notify_cb,
            _onopen: onopen,
            _onmessage: onmessage,
            _onerror: onerror,
            _onclose: onclose,
        };

        Ok((transport, open_rx))
    }

    /// Send a JSON-RPC request and await the response `result` value.
    ///
    /// Returns `Err(String)` if the relay responds with an `error` object, if
    /// the connection drops before a response arrives, or if the send fails.
    pub async fn send_request(&self, method: &str, params: Value) -> Result<Value, String> {
        let id = self.next_id.get();
        self.next_id.set(id + 1);

        let request = serde_json::json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": method,
            "params": params,
        });

        let (tx, rx) = oneshot::channel();
        self.pending.borrow_mut().insert(id, tx);

        // serde_json::to_string on a derived Serialize cannot fail
        let text = serde_json::to_string(&request).unwrap();
        if let Err(e) = self.ws.send_with_str(&text) {
            self.pending.borrow_mut().remove(&id);
            return Err(format!("send error: {:?}", e));
        }

        rx.await.map_err(|_| "request cancelled".to_string())?
    }

    /// Register a Rust callback to receive incoming notifications (server-initiated
    /// JSON-RPC messages with a `method` field but no `id`).
    ///
    /// The callback is invoked with the already-parsed `serde_json::Value` of
    /// the notification frame — no second JSON parse is needed on the caller side.
    pub fn set_notify_callback(&self, cb: Box<dyn FnMut(Value)>) {
        *self.notify_cb.borrow_mut() = Some(cb);
    }

    /// Close the WebSocket connection.
    pub fn close(&self) {
        let _ = self.ws.close();
    }
}

impl Drop for WasmTransport {
    /// Close the underlying WebSocket with a normal closure code (1000) when
    /// the transport is dropped.  Without this, the browser keeps the socket
    /// open after the Rust side releases the handle, leaking the connection.
    fn drop(&mut self) {
        let _ = self.ws.close_with_code(1000);
    }
}
