use std::collections::HashSet;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use image_hasher::ImageHash;
use rusqlite::Connection;
use serenity::model::id::{ChannelId, GuildId, MessageId, UserId};
use tokio::sync::Mutex;

/// Detects a strong sign of a compromised account: the same user posting the
/// same image (even if it doesn't match any known reference) across several
/// different channels **of the same guild** in a short time — typical of a
/// self-bot/webhook blasting a scam everywhere it has access to. Scoped by
/// guild so a user who happens to be in several of the bot's servers doesn't
/// get flagged for posting in two unrelated servers.
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

/// A flood that just crossed the threshold.
#[derive(Debug, PartialEq)]
pub struct FloodHit {
    /// Distinct channels hit by (a variant of) the same image.
    pub channels: usize,
    /// The *earlier* posts of that same image (not the one that triggered the
    /// detection), so the caller can clean them up too — otherwise only the
    /// last post of the flood ever gets deleted.
    pub earlier_messages: Vec<(ChannelId, MessageId)>,
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
            );",
        )
        .context("could not initialize flood_posts table")?;

        // Migrate a pre-multi-guild database (this table used to have no
        // guild_id column at all). Fails harmlessly with "duplicate column"
        // on a table that already has it — including one just created above.
        let _ = conn.execute(
            "ALTER TABLE flood_posts ADD COLUMN guild_id TEXT NOT NULL DEFAULT ''",
            [],
        );

        // Same migration pattern: older databases have no message_id column.
        // '' means "unknown / already handed out for deletion".
        let _ = conn.execute(
            "ALTER TABLE flood_posts ADD COLUMN message_id TEXT NOT NULL DEFAULT ''",
            [],
        );

        conn.execute_batch(
            "CREATE INDEX IF NOT EXISTS idx_flood_posts_guild_user_ts
                ON flood_posts(guild_id, user_id, ts);",
        )
        .context("could not create flood_posts index")?;

        Ok(Self {
            conn: Mutex::new(conn),
            window_seconds: window_seconds as i64,
            same_image_threshold,
            min_channels,
        })
    }

    /// Records an image post and, if the flood threshold is exceeded, returns the
    /// number of distinct channels (within the same guild) hit by (a variant of)
    /// this same image plus the earlier posts that are part of the flood.
    ///
    /// Earlier posts are only returned once: their stored message id is cleared
    /// when handed out, so a 4th/5th post of the same flood doesn't re-return
    /// (and re-try deleting) messages that are already gone.
    pub async fn record_and_check(
        &self,
        guild: GuildId,
        user: UserId,
        channel: ChannelId,
        message: MessageId,
        hash: ImageHash,
    ) -> Option<FloodHit> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let cutoff = now - self.window_seconds;
        let guild_id = guild.get().to_string();
        let user_id = user.get().to_string();
        let channel_id = channel.get().to_string();
        let message_id = message.get().to_string();
        let hash_b64 = hash.to_base64();

        let conn = self.conn.lock().await;

        if let Err(e) = conn.execute("DELETE FROM flood_posts WHERE ts < ?1", [cutoff]) {
            tracing::warn!("flood db cleanup failed: {e}");
        }

        if let Err(e) = conn.execute(
            "INSERT INTO flood_posts (guild_id, user_id, channel_id, message_id, hash, ts) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            rusqlite::params![guild_id, user_id, channel_id, message_id, hash_b64, now],
        ) {
            tracing::warn!("flood db insert failed: {e}");
            return None;
        }

        let mut stmt = match conn.prepare(
            "SELECT id, channel_id, message_id, hash FROM flood_posts \
             WHERE guild_id = ?1 AND user_id = ?2 AND ts >= ?3",
        ) {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!("flood db query failed: {e}");
                return None;
            }
        };

        let rows = match stmt.query_map(rusqlite::params![guild_id, user_id, cutoff], |row| {
            let id: i64 = row.get(0)?;
            let channel_id: String = row.get(1)?;
            let message_id: String = row.get(2)?;
            let hash: String = row.get(3)?;
            Ok((id, channel_id, message_id, hash))
        }) {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!("flood db row mapping failed: {e}");
                return None;
            }
        };

        let mut channels = HashSet::new();
        let mut matched_rows = Vec::new();
        let mut earlier_messages = Vec::new();
        for (id, row_channel, row_message, hash_str) in rows.flatten() {
            if let Ok(other) = ImageHash::from_base64(&hash_str) {
                if hash.dist(&other) <= self.same_image_threshold {
                    matched_rows.push(id);
                    if row_message != message_id {
                        if let (Ok(c), Ok(m)) = (row_channel.parse::<u64>(), row_message.parse::<u64>()) {
                            if c != 0 && m != 0 {
                                earlier_messages.push((ChannelId::new(c), MessageId::new(m)));
                            }
                        }
                    }
                    channels.insert(row_channel);
                }
            }
        }
        drop(stmt);

        if channels.len() < self.min_channels {
            return None;
        }

        for id in matched_rows {
            if let Err(e) = conn.execute("UPDATE flood_posts SET message_id = '' WHERE id = ?1", [id]) {
                tracing::warn!("flood db update failed: {e}");
            }
        }

        Some(FloodHit {
            channels: channels.len(),
            earlier_messages,
        })
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
        let guild = GuildId::new(1);
        let user = UserId::new(1);
        let hash = solid_color_hash(128);

        assert!(flood
            .record_and_check(guild, user, ChannelId::new(1), MessageId::new(100), hash.clone())
            .await
            .is_none());
        assert!(flood
            .record_and_check(guild, user, ChannelId::new(2), MessageId::new(200), hash.clone())
            .await
            .is_none());
        let result = flood.record_and_check(guild, user, ChannelId::new(3), MessageId::new(300), hash).await;
        assert_eq!(result.map(|h| h.channels), Some(3));
    }

    #[tokio::test]
    async fn ignores_different_images_across_channels() {
        let flood = FloodDetector::open(":memory:", 60, 6, 3).expect("open in-memory db");
        let guild = GuildId::new(1);
        let user = UserId::new(1);

        assert!(flood
            .record_and_check(guild, user, ChannelId::new(1), MessageId::new(100), noise_hash(1))
            .await
            .is_none());
        assert!(flood
            .record_and_check(guild, user, ChannelId::new(2), MessageId::new(200), noise_hash(2))
            .await
            .is_none());
        assert!(flood
            .record_and_check(guild, user, ChannelId::new(3), MessageId::new(300), noise_hash(3))
            .await
            .is_none());
    }

    /// Regression test: a detected flood must hand back the *earlier* posts too,
    /// otherwise only the post that crossed the threshold gets deleted and the
    /// rest of the spam stays up in the other channels. Each earlier post is only
    /// handed out once.
    #[tokio::test]
    async fn returns_the_earlier_posts_of_a_flood_once() {
        let flood = FloodDetector::open(":memory:", 60, 6, 3).expect("open in-memory db");
        let guild = GuildId::new(1);
        let user = UserId::new(1);
        let hash = solid_color_hash(128);

        flood.record_and_check(guild, user, ChannelId::new(1), MessageId::new(100), hash.clone()).await;
        flood.record_and_check(guild, user, ChannelId::new(2), MessageId::new(200), hash.clone()).await;
        let hit = flood
            .record_and_check(guild, user, ChannelId::new(3), MessageId::new(300), hash.clone())
            .await
            .expect("flood detected");
        let mut earlier = hit.earlier_messages;
        earlier.sort();
        assert_eq!(
            earlier,
            vec![
                (ChannelId::new(1), MessageId::new(100)),
                (ChannelId::new(2), MessageId::new(200)),
            ]
        );

        // A 4th post still counts as a flood, but must not re-return the posts
        // already handed out for deletion (nor the 3rd, deleted by the caller).
        let hit = flood
            .record_and_check(guild, user, ChannelId::new(4), MessageId::new(400), hash)
            .await
            .expect("flood still detected");
        assert_eq!(hit.channels, 4);
        assert!(hit.earlier_messages.is_empty());
    }

    /// The same user posting in 3 channels that happen to be spread across two
    /// *different* guilds must not be flagged — that's not cross-channel
    /// flooding of one server, just someone in two unrelated servers.
    #[tokio::test]
    async fn does_not_flag_across_different_guilds() {
        let flood = FloodDetector::open(":memory:", 60, 6, 3).expect("open in-memory db");
        let user = UserId::new(1);
        let hash = solid_color_hash(128);

        assert!(flood
            .record_and_check(GuildId::new(1), user, ChannelId::new(1), MessageId::new(100), hash.clone())
            .await
            .is_none());
        assert!(flood
            .record_and_check(GuildId::new(1), user, ChannelId::new(2), MessageId::new(200), hash.clone())
            .await
            .is_none());
        // Third post is in guild 2, not guild 1 — must not complete the guild-1 flood.
        assert!(flood
            .record_and_check(GuildId::new(2), user, ChannelId::new(3), MessageId::new(300), hash)
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

        let guild = GuildId::new(1);
        let user = UserId::new(42);
        let hash = solid_color_hash(200);

        {
            let flood = FloodDetector::open(&db_path, 60, 6, 3).expect("open db");
            flood.record_and_check(guild, user, ChannelId::new(1), MessageId::new(100), hash.clone()).await;
            flood.record_and_check(guild, user, ChannelId::new(2), MessageId::new(200), hash.clone()).await;
        } // "restart": the FloodDetector (and its connection) is dropped here.

        let flood = FloodDetector::open(&db_path, 60, 6, 3).expect("reopen db");
        let result = flood.record_and_check(guild, user, ChannelId::new(3), MessageId::new(300), hash).await;
        assert_eq!(result.map(|h| h.channels), Some(3), "flood history should persist across a restart");

        let _ = std::fs::remove_file(&db_path);
    }

    /// Regression test: opening a database created by a pre-multi-guild build
    /// (whose `flood_posts` table has no `guild_id` column at all) must not
    /// fail — this exact scenario broke a real deployment once.
    #[tokio::test]
    async fn opens_a_pre_multi_guild_database() {
        let db_path = std::env::temp_dir().join(format!(
            "discord_anti_scam_bot_flood_migration_test_{}.sqlite3",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&db_path);

        {
            let conn = Connection::open(&db_path).expect("create old-schema db");
            conn.execute_batch(
                "CREATE TABLE flood_posts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id TEXT NOT NULL,
                    channel_id TEXT NOT NULL,
                    hash TEXT NOT NULL,
                    ts INTEGER NOT NULL
                );",
            )
            .expect("create old flood_posts table");
            conn.execute(
                "INSERT INTO flood_posts (user_id, channel_id, hash, ts) VALUES ('1', '1', 'x', 0)",
                [],
            )
            .expect("insert old-schema row");
        }

        // Must open (and add the missing column) without erroring.
        let flood = FloodDetector::open(&db_path, 60, 6, 3).expect("open pre-migration db");
        let result = flood
            .record_and_check(GuildId::new(1), UserId::new(1), ChannelId::new(1), MessageId::new(100), solid_color_hash(1))
            .await;
        assert_eq!(result, None);

        let _ = std::fs::remove_file(&db_path);
    }
}
