use std::collections::VecDeque;
use std::time::{Duration, Instant};

use serenity::model::id::{ChannelId, GuildId, MessageId, UserId};
use tokio::sync::Mutex;

use crate::hashstore::ImageVariants;

/// Where an image was posted — enough to delete it and sanction its author
/// later, without keeping the whole `Message` around.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Post {
    pub guild_id: GuildId,
    pub channel_id: ChannelId,
    pub message_id: MessageId,
    pub author_id: UserId,
}

struct Entry {
    post: Post,
    hash: ImageVariants,
    at: Instant,
}

/// The hashes of the images recently posted that did *not* trigger a detection,
/// so a reference added a few minutes into a scam wave also catches the posts
/// that got through before it existed ("retro-scan"), instead of only future
/// ones. In memory only: this is a short look-back window, not history — losing
/// it on restart just means the retro-scan finds nothing that time.
///
/// Holds hashes, never image bytes (a few hundred bytes per entry), bounded by
/// both age and count.
pub struct RecentMedia {
    entries: Mutex<VecDeque<Entry>>,
    max_age: Duration,
    max_entries: usize,
}

impl RecentMedia {
    pub fn new(max_age: Duration, max_entries: usize) -> Self {
        Self {
            entries: Mutex::new(VecDeque::new()),
            max_age,
            max_entries,
        }
    }

    pub async fn record(&self, post: Post, hash: ImageVariants) {
        if self.max_entries == 0 || self.max_age.is_zero() {
            return;
        }
        let mut entries = self.entries.lock().await;
        Self::expire(&mut entries, self.max_age);
        while entries.len() >= self.max_entries {
            entries.pop_front();
        }
        entries.push_back(Entry { post, hash, at: Instant::now() });
    }

    /// Removes and returns every recent post whose image is within `threshold`
    /// of `reference` (same comparison as a normal reference match), one entry
    /// per distinct message, with the distance.
    pub async fn take_matches(&self, reference: &ImageVariants, threshold: u32) -> Vec<(Post, u32)> {
        let mut entries = self.entries.lock().await;
        Self::expire(&mut entries, self.max_age);

        let mut matched: Vec<(Post, u32)> = Vec::new();
        entries.retain(|e| {
            let distance = e.hash.min_dist(reference);
            if distance > threshold {
                return true;
            }
            // A multi-image message can be in here more than once.
            if !matched.iter().any(|(p, _)| p.message_id == e.post.message_id) {
                matched.push((e.post, distance));
            }
            false
        });
        matched
    }

    /// Every recent image post by `author` in `guild` whose message was created
    /// within `window` before or after `center` (by Discord snowflake time, not
    /// arrival time), left in place. Used to sweep a flagged author's other posts.
    pub async fn author_window(
        &self,
        guild: GuildId,
        author: UserId,
        center: MessageId,
        window: Duration,
    ) -> Vec<(Post, ImageVariants)> {
        let center = center.created_at().unix_timestamp();
        let window = window.as_secs() as i64;
        let mut entries = self.entries.lock().await;
        Self::expire(&mut entries, self.max_age);
        entries
            .iter()
            .filter(|e| e.post.guild_id == guild && e.post.author_id == author)
            .filter(|e| (e.post.message_id.created_at().unix_timestamp() - center).abs() <= window)
            .map(|e| (e.post, e.hash.clone()))
            .collect()
    }

    /// Drops these messages from the look-back window — they were already handled
    /// (e.g. the earlier posts of a detected flood), so a later retro-scan must
    /// not delete/sanction/log them a second time.
    pub async fn forget(&self, messages: &[MessageId]) {
        if messages.is_empty() {
            return;
        }
        self.entries.lock().await.retain(|e| !messages.contains(&e.post.message_id));
    }

    fn expire(entries: &mut VecDeque<Entry>, max_age: Duration) {
        while entries.front().is_some_and(|e| e.at.elapsed() > max_age) {
            entries.pop_front();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hashstore::ReferenceStore;

    fn post(message: u64, author: u64) -> Post {
        Post {
            guild_id: GuildId::new(1),
            channel_id: ChannelId::new(message),
            message_id: MessageId::new(message),
            author_id: UserId::new(author),
        }
    }

    fn hash(store: &ReferenceStore, path: &str) -> ImageVariants {
        store.hash_bytes(&std::fs::read(path).expect("read image")).expect("hash image")
    }

    #[tokio::test]
    async fn finds_recent_posts_of_a_newly_added_reference_once() {
        let store = ReferenceStore::new("reference");
        let recent = RecentMedia::new(Duration::from_secs(60), 100);

        recent.record(post(1, 10), hash(&store, "reference/image3.jpg")).await;
        recent.record(post(2, 11), hash(&store, "reference/image4.jpg")).await;
        recent.record(post(3, 10), hash(&store, "reference/image3.jpg")).await;

        let reference = hash(&store, "reference/image3.jpg");
        let mut matched: Vec<u64> =
            recent.take_matches(&reference, 18).await.iter().map(|(p, _)| p.message_id.get()).collect();
        matched.sort();
        assert_eq!(matched, vec![1, 3]);

        // Taken out of the cache: a second retro-scan doesn't act on them again.
        assert!(recent.take_matches(&reference, 18).await.is_empty());
    }

    #[tokio::test]
    async fn forgotten_posts_are_not_retro_matched() {
        let store = ReferenceStore::new("reference");
        let recent = RecentMedia::new(Duration::from_secs(60), 100);
        recent.record(post(1, 10), hash(&store, "reference/image3.jpg")).await;
        recent.record(post(2, 10), hash(&store, "reference/image3.jpg")).await;

        recent.forget(&[MessageId::new(1)]).await;

        let matched = recent.take_matches(&hash(&store, "reference/image3.jpg"), 18).await;
        assert_eq!(matched.iter().map(|(p, _)| p.message_id.get()).collect::<Vec<_>>(), vec![2]);
    }

    #[tokio::test]
    async fn author_window_only_returns_that_author_in_that_guild_and_time_range() {
        let store = ReferenceStore::new("reference");
        let recent = RecentMedia::new(Duration::from_secs(3600), 100);
        let h = || hash(&store, "reference/image4.jpg");
        // Snowflake for a given unix time (ms) — message times come from the id.
        let at = |secs: u64, n: u64| MessageId::new(((secs * 1000 - 1_420_070_400_000) << 22) + n);
        let t = 1_790_000_000;
        let mk = |id: MessageId, guild: u64, author: u64| Post {
            guild_id: GuildId::new(guild),
            channel_id: ChannelId::new(1),
            message_id: id,
            author_id: UserId::new(author),
        };

        recent.record(mk(at(t - 20 * 60, 1), 1, 10), h()).await; // in window
        recent.record(mk(at(t + 10 * 60, 2), 1, 10), h()).await; // in window (after)
        recent.record(mk(at(t - 45 * 60, 3), 1, 10), h()).await; // too early
        recent.record(mk(at(t, 4), 1, 11), h()).await; // other author
        recent.record(mk(at(t, 5), 2, 10), h()).await; // other guild

        let found = recent
            .author_window(GuildId::new(1), UserId::new(10), at(t, 0), Duration::from_secs(30 * 60))
            .await;
        let mut ids: Vec<u64> = found.iter().map(|(p, _)| p.message_id.get() & 0xfff).collect();
        ids.sort();
        assert_eq!(ids, vec![1, 2]);
    }

    #[tokio::test]
    async fn is_bounded_by_count() {
        let store = ReferenceStore::new("reference");
        let recent = RecentMedia::new(Duration::from_secs(60), 2);
        for i in 1..=3 {
            recent.record(post(i, 10), hash(&store, "reference/image3.jpg")).await;
        }
        let reference = hash(&store, "reference/image3.jpg");
        let mut matched: Vec<u64> =
            recent.take_matches(&reference, 18).await.iter().map(|(p, _)| p.message_id.get()).collect();
        matched.sort();
        assert_eq!(matched, vec![2, 3], "the oldest entry should have been evicted");
    }
}
