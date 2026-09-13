use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

use image_hasher::ImageHash;
use serenity::model::id::{ChannelId, UserId};
use tokio::sync::Mutex;

struct Post {
    channel_id: ChannelId,
    hash: ImageHash,
    at: Instant,
}

/// Detects a strong sign of a compromised account: the same user posting the
/// same image (even if it doesn't match any known reference) across several
/// different channels in a short time — typical of a self-bot/webhook blasting
/// a scam everywhere it has access to.
pub struct FloodDetector {
    window: Duration,
    same_image_threshold: u32,
    min_channels: usize,
    recent: Mutex<HashMap<UserId, Vec<Post>>>,
}

impl FloodDetector {
    pub fn new(window_seconds: u64, same_image_threshold: u32, min_channels: usize) -> Self {
        Self {
            window: Duration::from_secs(window_seconds),
            same_image_threshold,
            min_channels,
            recent: Mutex::new(HashMap::new()),
        }
    }

    /// Records an image post and returns the number of distinct channels hit by
    /// (a variant of) this same image if the flood threshold is exceeded.
    pub async fn record_and_check(
        &self,
        user: UserId,
        channel: ChannelId,
        hash: ImageHash,
    ) -> Option<usize> {
        let mut map = self.recent.lock().await;
        let posts = map.entry(user).or_default();
        let now = Instant::now();
        posts.retain(|p| now.duration_since(p.at) < self.window);

        let mut channels: HashSet<ChannelId> = posts
            .iter()
            .filter(|p| p.hash.dist(&hash) <= self.same_image_threshold)
            .map(|p| p.channel_id)
            .collect();
        channels.insert(channel);

        posts.push(Post {
            channel_id: channel,
            hash,
            at: now,
        });

        if channels.len() >= self.min_channels {
            Some(channels.len())
        } else {
            None
        }
    }

    /// Periodic cleanup of expired entries so memory doesn't grow unbounded.
    pub async fn sweep(&self) {
        let mut map = self.recent.lock().await;
        let now = Instant::now();
        map.retain(|_, posts| {
            posts.retain(|p| now.duration_since(p.at) < self.window);
            !posts.is_empty()
        });
    }
}
