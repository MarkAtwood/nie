//! Cross-instance message bus for horizontal relay scaling.
//!
//! A single relay process delivers messages only to the clients connected
//! locally.  When multiple relay instances share the same user base, a
//! message from a client on instance A must also reach clients connected to
//! instances B, C, etc.  The `MessageBus` abstracts this cross-instance
//! delivery channel.
//!
//! # Variants
//!
//! | Variant | When to use |
//! |---------|-------------|
//! | `LocalBus` | Single-process deployment (default) |
//! | `RedisBus` | Multi-instance behind a load balancer (enable `redis-bus` feature) |
//!
//! # Wire format
//!
//! Every message on the bus is a JSON-encoded `BusMessage`.  The relay
//! receiver task deserialises it and delivers the payload locally to any
//! matching connected client.
//!
//! # Usage
//!
//! ```text
//! // startup
//! let bus = Arc::new(MessageBus::local());
//! // …or, with Redis feature enabled:
//! let bus = Arc::new(MessageBus::redis("redis://127.0.0.1/").await?);
//!
//! // broadcast path — relay publishes after local delivery
//! bus.publish(&BusMessage::Broadcast { exclude, payload }).await?;
//!
//! // subscription task — relay receives from other instances
//! let mut sub = bus.subscribe().await?;
//! while let Some(msg) = sub.recv().await { ... }
//! ```

use anyhow::Result;
use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;

// ---- Bus message types ----

/// A message relayed between relay instances via the bus.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum BusMessage {
    /// Fan-out to all clients on the receiving instance, optionally excluding one sender.
    Broadcast {
        /// pub_id to exclude from delivery (the original sender), or `None` to deliver to all.
        exclude: Option<String>,
        /// Pre-serialized JSON-RPC notification string.
        payload: String,
    },
    /// Point-to-point delivery to a specific client.
    Direct {
        /// Target pub_id.
        to: String,
        /// Pre-serialized JSON-RPC notification string.
        payload: String,
    },
}

// ---- Subscriber handle ----

/// A handle for receiving cross-instance messages.
pub struct BusSubscriber {
    inner: SubscriberInner,
}

enum SubscriberInner {
    /// Single-instance: never yields anything (all delivery is already local).
    Local(broadcast::Receiver<BusMessage>),
    #[cfg(feature = "redis-bus")]
    Redis(Box<RedisSubscriber>),
}

impl BusSubscriber {
    /// Receive the next cross-instance message, or `None` on shutdown.
    pub async fn recv(&mut self) -> Option<BusMessage> {
        match &mut self.inner {
            SubscriberInner::Local(rx) => {
                // Drain messages or block until one arrives.
                // Loop instead of recursing on Lagged to prevent unbounded stack growth
                // in a sustained-lag scenario (e.g. slow consumer on a busy channel).
                loop {
                    match rx.recv().await {
                        Ok(msg) => return Some(msg),
                        Err(broadcast::error::RecvError::Closed) => return None,
                        Err(broadcast::error::RecvError::Lagged(n)) => {
                            tracing::warn!("LocalBus receiver lagged, dropped {} messages", n);
                            continue;
                        }
                    }
                }
            }
            #[cfg(feature = "redis-bus")]
            SubscriberInner::Redis(sub) => sub.recv().await,
        }
    }
}

// ---- MessageBus ----

/// Cross-instance message bus.
///
/// Clone is cheap (`Arc` under the hood on the Redis path; copy for Local).
#[derive(Clone)]
pub struct MessageBus {
    inner: BusInner,
}

#[derive(Clone)]
enum BusInner {
    Local(broadcast::Sender<BusMessage>),
    #[cfg(feature = "redis-bus")]
    Redis(std::sync::Arc<RedisClient>),
}

impl MessageBus {
    /// Create a local (single-process) bus.
    ///
    /// The local bus uses a tokio broadcast channel with capacity 1024.
    /// On a single-process deployment this is almost always a no-op
    /// (the relay delivers directly without going through the bus), but it
    /// allows the same code paths to be exercised in tests.
    pub fn local() -> Self {
        let (tx, _) = broadcast::channel(1024);
        Self {
            inner: BusInner::Local(tx),
        }
    }

    /// Create a Redis-backed message bus.
    ///
    /// Requires the `redis-bus` Cargo feature.
    #[cfg(feature = "redis-bus")]
    pub async fn redis(url: &str) -> Result<Self> {
        let client = redis::Client::open(url)?;
        Ok(Self {
            inner: BusInner::Redis(std::sync::Arc::new(RedisClient { client })),
        })
    }

    /// Publish a message to all other relay instances.
    ///
    /// On the local bus this broadcasts to any subscribers within the same
    /// process (useful for tests).  On the Redis bus this publishes to the
    /// `"nie:relay:bus"` channel.
    pub async fn publish(&self, msg: &BusMessage) -> Result<()> {
        match &self.inner {
            BusInner::Local(tx) => {
                // Ignore SendError: no subscribers is fine for single-instance.
                let _ = tx.send(msg.clone());
                Ok(())
            }
            #[cfg(feature = "redis-bus")]
            BusInner::Redis(c) => c.publish(msg).await,
        }
    }

    /// Subscribe to cross-instance messages.
    ///
    /// The returned `BusSubscriber` yields messages published by other relay
    /// instances (or, on the local bus, by `publish` within the same process).
    ///
    /// # Note
    ///
    /// `main.rs` does not currently spawn a subscriber task — cross-instance
    /// fan-out via the bus is not yet wired end-to-end.  This method exists for
    /// the future `redis-bus` multi-instance path and is exercised by unit tests.
    pub async fn subscribe(&self) -> Result<BusSubscriber> {
        match &self.inner {
            BusInner::Local(tx) => Ok(BusSubscriber {
                inner: SubscriberInner::Local(tx.subscribe()),
            }),
            #[cfg(feature = "redis-bus")]
            BusInner::Redis(c) => {
                let sub = c.subscribe().await?;
                Ok(BusSubscriber {
                    inner: SubscriberInner::Redis(Box::new(sub)),
                })
            }
        }
    }
}

// ---- Redis implementation (feature-gated) ----

#[cfg(feature = "redis-bus")]
const REDIS_CHANNEL: &str = "nie:relay:bus";

#[cfg(feature = "redis-bus")]
struct RedisClient {
    client: redis::Client,
}

#[cfg(feature = "redis-bus")]
impl RedisClient {
    async fn publish(&self, msg: &BusMessage) -> Result<()> {
        use redis::AsyncCommands;
        let mut conn = self
            .client
            .get_multiplexed_async_connection()
            .await
            .map_err(|e| anyhow::anyhow!("Redis connection error: {e}"))?;
        let payload =
            serde_json::to_string(msg).map_err(|e| anyhow::anyhow!("bus serialize error: {e}"))?;
        conn.publish::<_, _, ()>(REDIS_CHANNEL, payload)
            .await
            .map_err(|e| anyhow::anyhow!("Redis publish error: {e}"))?;
        Ok(())
    }

    async fn subscribe(&self) -> Result<RedisSubscriber> {
        let mut conn = self
            .client
            .get_async_pubsub()
            .await
            .map_err(|e| anyhow::anyhow!("Redis pubsub connection error: {e}"))?;
        conn.subscribe(REDIS_CHANNEL)
            .await
            .map_err(|e| anyhow::anyhow!("Redis SUBSCRIBE error: {e}"))?;
        Ok(RedisSubscriber { conn })
    }
}

#[cfg(feature = "redis-bus")]
struct RedisSubscriber {
    conn: redis::aio::PubSub,
}

#[cfg(feature = "redis-bus")]
impl RedisSubscriber {
    async fn recv(&mut self) -> Option<BusMessage> {
        use futures::StreamExt;
        loop {
            let msg = self.conn.on_message().next().await?;
            let payload: String = match msg.get_payload() {
                Ok(p) => p,
                Err(e) => {
                    tracing::warn!("RedisSubscriber: failed to extract payload: {e}");
                    continue;
                }
            };
            match serde_json::from_str::<BusMessage>(&payload) {
                Ok(m) => return Some(m),
                Err(e) => {
                    tracing::warn!("RedisSubscriber: failed to deserialize bus message: {e}");
                    continue;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn local_bus_publish_and_receive() {
        let bus = MessageBus::local();
        let mut sub = bus.subscribe().await.unwrap();

        let msg = BusMessage::Broadcast {
            exclude: Some("alice".to_string()),
            payload: "hello".to_string(),
        };
        bus.publish(&msg).await.unwrap();

        let received = sub.recv().await.unwrap();
        match received {
            BusMessage::Broadcast { exclude, payload } => {
                assert_eq!(exclude.as_deref(), Some("alice"));
                assert_eq!(payload, "hello");
            }
            _ => panic!("wrong message type"),
        }
    }

    #[tokio::test]
    async fn local_bus_direct_message() {
        let bus = MessageBus::local();
        let mut sub = bus.subscribe().await.unwrap();

        let msg = BusMessage::Direct {
            to: "bob".to_string(),
            payload: "dm payload".to_string(),
        };
        bus.publish(&msg).await.unwrap();

        let received = sub.recv().await.unwrap();
        match received {
            BusMessage::Direct { to, payload } => {
                assert_eq!(to, "bob");
                assert_eq!(payload, "dm payload");
            }
            _ => panic!("wrong message type"),
        }
    }

    #[tokio::test]
    async fn bus_message_roundtrip_json() {
        let msg = BusMessage::Broadcast {
            exclude: None,
            payload: r#"{"jsonrpc":"2.0"}"#.to_string(),
        };
        let json = serde_json::to_string(&msg).unwrap();
        let decoded: BusMessage = serde_json::from_str(&json).unwrap();
        match decoded {
            BusMessage::Broadcast { exclude, payload } => {
                assert!(exclude.is_none());
                assert_eq!(payload, r#"{"jsonrpc":"2.0"}"#);
            }
            _ => panic!("wrong variant"),
        }
    }
}
