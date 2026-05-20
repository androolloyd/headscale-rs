//! Payment channels for streaming micropayments.

use std::collections::HashMap;
use std::sync::Arc;

use tokio::sync::RwLock;

/// A payment channel for streaming micropayments.
pub struct PaymentChannel {
    /// Channel state
    channels: Arc<RwLock<HashMap<String, ChannelState>>>,
}

/// State of a payment channel.
#[derive(Debug, Clone)]
pub struct ChannelState {
    pub id: String,
    pub sender: String,
    pub receiver: String,
    pub capacity: u64,
    pub sent: u64,
    pub received: u64,
    pub state: ChannelStatus,
    pub created_at: u64,
    pub last_update: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChannelStatus {
    Open,
    Closing,
    Closed,
    Disputed,
}

impl PaymentChannel {
    pub fn new() -> Self {
        Self {
            channels: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Open a new payment channel.
    pub async fn open(
        &self,
        sender: &str,
        receiver: &str,
        capacity: u64,
    ) -> Result<String, ChannelError> {
        let id = generate_channel_id();

        let state = ChannelState {
            id: id.clone(),
            sender: sender.to_string(),
            receiver: receiver.to_string(),
            capacity,
            sent: 0,
            received: 0,
            state: ChannelStatus::Open,
            created_at: now(),
            last_update: now(),
        };

        self.channels.write().await.insert(id.clone(), state);
        Ok(id)
    }

    /// Send a micropayment through the channel.
    pub async fn send(&self, channel_id: &str, amount: u64) -> Result<u64, ChannelError> {
        let mut channels = self.channels.write().await;
        let channel = channels.get_mut(channel_id).ok_or(ChannelError::NotFound)?;

        if channel.state != ChannelStatus::Open {
            return Err(ChannelError::NotOpen);
        }

        if channel.sent + amount > channel.capacity {
            return Err(ChannelError::InsufficientCapacity);
        }

        channel.sent += amount;
        channel.received += amount;
        channel.last_update = now();

        Ok(channel.sent)
    }

    /// Get current channel balance.
    pub async fn balance(&self, channel_id: &str) -> Result<(u64, u64), ChannelError> {
        let channels = self.channels.read().await;
        let channel = channels.get(channel_id).ok_or(ChannelError::NotFound)?;
        Ok((channel.capacity - channel.sent, channel.received))
    }

    /// Close a channel.
    pub async fn close(&self, channel_id: &str) -> Result<ChannelState, ChannelError> {
        let mut channels = self.channels.write().await;
        let channel = channels.get_mut(channel_id).ok_or(ChannelError::NotFound)?;

        channel.state = ChannelStatus::Closed;
        channel.last_update = now();

        Ok(channel.clone())
    }

    /// Get channel state.
    pub async fn get(&self, channel_id: &str) -> Option<ChannelState> {
        self.channels.read().await.get(channel_id).cloned()
    }
}

impl Default for PaymentChannel {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ChannelError {
    #[error("Channel not found")]
    NotFound,
    #[error("Channel not open")]
    NotOpen,
    #[error("Insufficient channel capacity")]
    InsufficientCapacity,
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn generate_channel_id() -> String {
    format!("channel_{}", now())
}
