use std::collections::HashSet;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use image_hasher::ImageHash;
use rusqlite::Connection;
use serenity::model::id::{ChannelId, UserId};
use tokio::sync::Mutex;

/// Detects a strong sign of a compromised account: the same user posting the
/// same image (even if it doesn't match any known reference) across several
/// different channels in a short time — typical of a self-bot/webhook blasting
/// a scam everywhere it has access to.
///
/// Backed by SQLite (instead of an in-memory map) so this survives a bot restart:
/// a scammer's post history a moment before a redeploy shouldn't be forgotten.
/// Queries are tiny (a handful of rows per user, over a short time window), so
/// holding the connection behind a plain async mutex is enough — no need for a
/// dedicated blocking-task pool here.
pub struct FloodDetector {
    conn: Mutex<Connection>,
    window_seconds: i64,
    same_image_threshold: u32,
    min_channels: usize,
}

impl FloodDetector {
    pub fn open(
        db_path: impl AsRef<Path>,
        window_seconds: u64,
        same_image_threshold: u32,
        min_channels: usize,
    ) -> Result<Self> {
        let db_path = db_path.as_ref();
        if let Some(parent) = db_path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)
                    .with_context(|| format!("could not create folder {}", parent.display()))?;
            }
        }

        let conn = Connection::open(db_path)
            .with_context(|| format!("could not open database {}", db_path.display()))?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS flood_posts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT NOT NULL,
                channel_id TEXT NOT NULL,
                hash TEXT NOT NULL,
                ts INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_flood_posts_user_ts ON flood_posts(user_id, ts);",
        )
        .context("could not initialize flood_posts table")?;

        Ok(Self {
            conn: Mutex::new(conn),
            window_seconds: window_seconds as i64,
            same_image_threshold,
            min_channels,
        })
    }

    /// Records an image post and returns the number of distinct channels hit by
    /// (a variant of) this same image if the flood threshold is exceeded.
    pub async fn record_and_check(
        &self,
        user: UserId,
        channel: ChannelId,
        hash: ImageHash,
    ) -> Option<usize> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let cutoff = now - self.window_seconds;
        let user_id = user.get().to_string();
        let channel_id = channel.get().to_string();
        let hash_b64 = hash.to_base64();

        let conn = self.conn.lock().await;

        if let Err(e) = conn.execute("DELETE FROM flood_posts WHERE ts < ?1", [cutoff]) {
            tracing::warn!("flood db cleanup failed: {e}");
        }

        if let Err(e) = conn.execute(
            "INSERT INTO flood_posts (user_id, channel_id, hash, ts) VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![user_id, channel_id, hash_b64, now],
        ) {
            tracing::warn!("flood db insert failed: {e}");
            return None;
        }

        let mut stmt = match conn
            .prepare("SELECT channel_id, hash FROM flood_posts WHERE user_id = ?1 AND ts >= ?2")
        {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!("flood db query failed: {e}");
                return None;
            }
        };

        let rows = match stmt.query_map(rusqlite::params![user_id, cutoff], |row| {
            let channel_id: String = row.get(0)?;
            let hash: String = row.get(1)?;
            Ok((channel_id, hash))
        }) {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!("flood db row mapping failed: {e}");
                return None;
            }
        };

        let mut channels = HashSet::new();
        for (channel_id, hash_str) in rows.flatten() {
            if let Ok(other) = ImageHash::from_base64(&hash_str) {
                if hash.dist(&other) <= self.same_image_threshold {
                    channels.insert(channel_id);
                }
            }
        }

        if channels.len() >= self.min_channels {
            Some(channels.len())
        } else {
            None
        }
    }

    /// Periodic cleanup of expired rows, for when the bot goes quiet for a while
    /// (a live account's own post would already trigger the cleanup above, but an
    /// idle server shouldn't keep growing the table indefinitely either).
    pub async fn sweep(&self) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let cutoff = now - self.window_seconds;
        let conn = self.conn.lock().await;
        if let Err(e) = conn.execute("DELETE FROM flood_posts WHERE ts < ?1", [cutoff]) {
            tracing::warn!("flood db sweep failed: {e}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use image_hasher::{HashAlg, HasherConfig};

    fn solid_color_hash(value: u8) -> ImageHash {
        let img = image::RgbImage::from_pixel(16, 16, image::Rgb([value, value, value]));
        let hasher = HasherConfig::new()
            .hash_alg(HashAlg::DoubleGradient)
            .hash_size(16, 16)
            .to_hasher();
        hasher.hash_image(&image::DynamicImage::ImageRgb8(img))
    }

    /// A solid color hashes the same regardless of the color (gradient-based
    /// hashing is invariant to constant brightness), so genuinely distinct test
    /// images need actual internal variation — deterministic per-seed noise.
    fn noise_hash(seed: u64) -> ImageHash {
        let mut state = seed.wrapping_mul(2685821657736338717).wrapping_add(1);
        let mut img = image::RgbImage::new(16, 16);
        for p in img.pixels_mut() {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            let v = (state & 0xff) as u8;
            *p = image::Rgb([v, v.wrapping_add(64), v.wrapping_add(128)]);
        }
        let hasher = HasherConfig::new()
            .hash_alg(HashAlg::DoubleGradient)
            .hash_size(16, 16)
            .to_hasher();
        hasher.hash_image(&image::DynamicImage::ImageRgb8(img))
    }

    #[tokio::test]
    async fn flags_the_same_image_across_enough_channels() {
        let flood = FloodDetector::open(":memory:", 60, 6, 3).expect("open in-memory db");
        let user = UserId::new(1);
        let hash = solid_color_hash(128);

        assert!(flood
            .record_and_check(user, ChannelId::new(1), hash.clone())
            .await
            .is_none());
        assert!(flood
            .record_and_check(user, ChannelId::new(2), hash.clone())
            .await
            .is_none());
        let result = flood
            .record_and_check(user, ChannelId::new(3), hash)
            .await;
        assert_eq!(result, Some(3));
    }

    #[tokio::test]
    async fn ignores_different_images_across_channels() {
        let flood = FloodDetector::open(":memory:", 60, 6, 3).expect("open in-memory db");
        let user = UserId::new(1);

        assert!(flood
            .record_and_check(user, ChannelId::new(1), noise_hash(1))
            .await
            .is_none());
        assert!(flood
            .record_and_check(user, ChannelId::new(2), noise_hash(2))
            .await
            .is_none());
        assert!(flood
            .record_and_check(user, ChannelId::new(3), noise_hash(3))
            .await
            .is_none());
    }

    #[tokio::test]
    async fn survives_a_restart() {
        let db_path = std::env::temp_dir().join(format!(
            "discord_anti_scam_bot_flood_test_{}.sqlite3",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&db_path);

        let user = UserId::new(42);
        let hash = solid_color_hash(200);

        {
            let flood = FloodDetector::open(&db_path, 60, 6, 3).expect("open db");
            flood
                .record_and_check(user, ChannelId::new(1), hash.clone())
                .await;
            flood
                .record_and_check(user, ChannelId::new(2), hash.clone())
                .await;
        } // "restart": the FloodDetector (and its connection) is dropped here.

        let flood = FloodDetector::open(&db_path, 60, 6, 3).expect("reopen db");
        let result = flood
            .record_and_check(user, ChannelId::new(3), hash)
            .await;
        assert_eq!(result, Some(3), "flood history should persist across a restart");

        let _ = std::fs::remove_file(&db_path);
    }
}
