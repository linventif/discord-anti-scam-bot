use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use serenity::async_trait;
use serenity::builder::{CreateAttachment, CreateEmbed, CreateMessage};
use serenity::model::application::Interaction;
use serenity::model::channel::Message;
use serenity::model::colour::Colour;
use serenity::model::gateway::Ready;
use serenity::model::timestamp::Timestamp;
use serenity::prelude::*;

use crate::config::{Action, Config, GuildConfig};
use crate::configstore::ConfigStore;
use crate::flood::{FloodDetector, FloodHit};
use crate::guildstore::GuildSettingsStore;
use crate::hashstore::ReferenceStore;
use crate::linkimage::LinkImageFetcher;
use crate::ocr::OcrScanner;
use crate::recent::{Post, RecentMedia};

pub struct Handler {
    pub config: Arc<ConfigStore>,
    pub guild_settings: Arc<GuildSettingsStore>,
    pub store: Arc<ReferenceStore>,
    pub flood: Arc<FloodDetector>,
    pub links: LinkImageFetcher,
    /// `None` when OCR is disabled or tesseract isn't installed.
    pub ocr: Option<Arc<OcrScanner>>,
    /// Hashes of recent images that didn't trigger anything, for the retro-scan
    /// run whenever a reference is added (see `add_reference`).
    pub recent: RecentMedia,
}

/// Result of `Handler::add_reference`.
pub struct AddedReference {
    pub filename: String,
    /// Recent posts that matched the new reference and were handled.
    pub retro_matches: usize,
}

enum DetectionReason {
    KnownReference { reference: String, distance: u32 },
    CrossChannelFlood { channels: usize },
    ScamText { score: u32, matched: Vec<String> },
    /// A post from before the reference existed, caught by the retro-scan.
    RetroMatch { reference: String, distance: u32, messages: usize },
}

impl DetectionReason {
    fn title(&self) -> &'static str {
        match self {
            DetectionReason::KnownReference { .. } => "🚨 Image matches a known scam",
            DetectionReason::CrossChannelFlood { .. } => "🚨 Same image posted across multiple channels",
            DetectionReason::ScamText { .. } => "🚨 Image text matches a known scam pattern",
            DetectionReason::RetroMatch { .. } => "🚨 Recent post matches a newly added scam reference",
        }
    }

    fn description(&self) -> String {
        match self {
            DetectionReason::KnownReference { reference, distance } => format!(
                "Matches reference `{reference}` (hash distance: {distance})."
            ),
            DetectionReason::CrossChannelFlood { channels } => format!(
                "The same image was posted in {channels} different channels in a short time \
                 — a typical sign of a compromised account auto-spamming."
            ),
            DetectionReason::ScamText { score, matched } => {
                let mut phrases = matched
                    .iter()
                    .take(8)
                    .map(|p| format!("`{p}`"))
                    .collect::<Vec<_>>()
                    .join(", ");
                if matched.len() > 8 {
                    phrases.push_str(&format!(" (+{} more)", matched.len() - 8));
                }
                format!("Text read from the image (OCR) scored {score}. Matched: {phrases}.")
            }
            DetectionReason::RetroMatch { reference, distance, messages } => format!(
                "{messages} post(s) from the last few minutes match `{reference}` (hash distance: \
                 {distance}), added as a reference after they were posted."
            ),
        }
    }

    /// Review buttons for the log message: a detection caused by a reference can
    /// only be wrong because of that reference; any other detection can be
    /// confirmed (→ becomes a reference) or dismissed.
    fn review_buttons(&self, author: serenity::model::id::UserId) -> Vec<serenity::builder::CreateActionRow> {
        match self {
            DetectionReason::KnownReference { reference, .. } | DetectionReason::RetroMatch { reference, .. } => {
                crate::review::reference_buttons(Some(author), reference)
            }
            DetectionReason::CrossChannelFlood { .. } | DetectionReason::ScamText { .. } => {
                crate::review::unconfirmed_detection_buttons(author)
            }
        }
    }
}

#[async_trait]
impl EventHandler for Handler {
    async fn ready(&self, ctx: Context, ready: Ready) {
        tracing::info!("Logged in as {}", ready.user.name);
        tracing::info!("{} reference image(s) in memory", self.store.len().await);

        tracing::info!("in {} guild(s)", ready.guilds.len());

        // Global (not per-guild) so the command works in every server the bot is
        // in without needing a fresh `ready` event — e.g. after being removed and
        // re-added to a guild, which doesn't retrigger per-guild registration.
        let commands = vec![
            crate::slashconfig::build_config_command(),
            crate::review::build_add_reference_menu(),
        ];
        match serenity::model::application::Command::set_global_commands(&ctx.http, commands).await {
            Ok(_) => tracing::info!("/config + \"{}\" commands registered globally", crate::review::ADD_REFERENCE_MENU),
            Err(e) => tracing::warn!("could not register global commands: {e}"),
        }

        // Clean up the per-guild registrations from before this command became
        // global, so it doesn't show up twice while global propagation catches up.
        for guild in &ready.guilds {
            if let Err(e) = guild.id.set_commands(&ctx.http, Vec::new()).await {
                tracing::debug!("could not clear guild commands in {}: {e}", guild.id);
            }
        }
    }

    async fn interaction_create(&self, ctx: Context, interaction: Interaction) {
        match interaction {
            Interaction::Command(command) if command.data.name == "config" => {
                if let Err(e) = crate::slashconfig::handle_config_command(self, &ctx, &command).await {
                    tracing::warn!("error responding to /config: {e:#}");
                }
            }
            Interaction::Autocomplete(command) if command.data.name == "config" => {
                if let Err(e) = crate::slashconfig::handle_config_autocomplete(&ctx, &command).await {
                    tracing::warn!("error responding to /config autocomplete: {e:#}");
                }
            }
            Interaction::Command(command) if command.data.name == crate::review::ADD_REFERENCE_MENU => {
                if let Err(e) = crate::review::handle_add_reference_menu(self, &ctx, &command).await {
                    tracing::warn!("error handling \"{}\": {e:#}", crate::review::ADD_REFERENCE_MENU);
                }
            }
            Interaction::Component(component) if crate::review::is_review_button(&component.data.custom_id) => {
                if let Err(e) = crate::review::handle_review_button(self, &ctx, &component).await {
                    tracing::warn!("error handling review button: {e:#}");
                }
            }
            _ => {}
        }
    }

    async fn message(&self, ctx: Context, msg: Message) {
        let Some(guild_id) = msg.guild_id else {
            return;
        };
        if msg.author.bot {
            return;
        }

        let cfg = self.config.snapshot().await;
        let guild = self.guild_settings.get(guild_id.get()).await;

        if let Some(rest) = msg.content.strip_prefix(&cfg.bot.prefix) {
            if let Err(e) = crate::commands::handle_command(self, &guild, &ctx, &msg, rest.trim()).await {
                tracing::warn!("error while handling command: {e:#}");
            }
            return;
        }

        // A forwarded message carries its own content as a "snapshot" instead of
        // real attachments on this message — a multi-image scam forwarded from
        // another channel/server would otherwise be invisible to us.
        let has_attachments =
            !msg.attachments.is_empty() || msg.message_snapshots.iter().any(|s| !s.attachments.is_empty());

        if !has_attachments && !cfg.links.enabled {
            return;
        }

        if guild.exempt_channel_ids.contains(&msg.channel_id.get()) {
            return;
        }

        if let Ok(member) = msg.member(&ctx).await {
            let exempt = member.roles.iter().any(|r| guild.exempt_role_ids.contains(&r.get()));
            if exempt {
                return;
            }
        }

        if self
            .scan_attachments(&cfg, &guild, guild_id, &ctx, &msg, &msg.attachments)
            .await
        {
            return;
        }
        for snapshot in &msg.message_snapshots {
            if self
                .scan_attachments(&cfg, &guild, guild_id, &ctx, &msg, &snapshot.attachments)
                .await
            {
                return;
            }
        }

        if cfg.links.enabled {
            let texts = std::iter::once(msg.content.as_str())
                .chain(msg.message_snapshots.iter().map(|s| s.content.as_str()));
            for text in texts {
                if self.scan_links(&cfg, &guild, guild_id, &ctx, &msg, text).await {
                    return;
                }
            }
        }
    }
}

impl Handler {
    /// Downloads and checks every image attachment in a slice (either the
    /// message's own attachments, or one of its forwarded snapshots'). Returns
    /// `true` if a detection fired.
    async fn scan_attachments(
        &self,
        cfg: &Config,
        guild: &GuildConfig,
        guild_id: serenity::model::id::GuildId,
        ctx: &Context,
        msg: &Message,
        attachments: &[serenity::model::channel::Attachment],
    ) -> bool {
        for attachment in attachments {
            if !is_image_attachment(attachment) {
                continue;
            }

            let bytes = match attachment.download().await {
                Ok(b) => b,
                Err(e) => {
                    tracing::warn!(
                        "could not download attachment {}: {e}",
                        attachment.filename
                    );
                    continue;
                }
            };

            if self
                .evaluate_image(cfg, guild, guild_id, ctx, msg, &bytes, &attachment.filename)
                .await
            {
                return true;
            }
        }
        false
    }

    /// Extracts and checks every allow-listed image link in a piece of text
    /// (the message's own content, or a forwarded snapshot's). Returns `true` if
    /// a detection fired.
    async fn scan_links(
        &self,
        cfg: &Config,
        guild: &GuildConfig,
        guild_id: serenity::model::id::GuildId,
        ctx: &Context,
        msg: &Message,
        text: &str,
    ) -> bool {
        for url in self.links.extract_urls(text) {
            let bytes = match self.links.fetch_image_bytes(&url).await {
                Ok(Some(b)) => b,
                Ok(None) => continue,
                Err(e) => {
                    tracing::debug!("could not fetch linked image {url}: {e:#}");
                    continue;
                }
            };

            if self.evaluate_image(cfg, guild, guild_id, ctx, msg, &bytes, &url).await {
                return true;
            }
        }
        false
    }

    async fn evaluate_image(
        &self,
        cfg: &Config,
        guild: &GuildConfig,
        guild_id: serenity::model::id::GuildId,
        ctx: &Context,
        msg: &Message,
        bytes: &[u8],
        label: &str,
    ) -> bool {
        let hash = match self.store.hash_bytes(bytes) {
            Ok(h) => h,
            Err(e) => {
                tracing::debug!("could not hash {label}: {e}");
                return false;
            }
        };
        let post = Post {
            guild_id,
            channel_id: msg.channel_id,
            message_id: msg.id,
            author_id: msg.author.id,
        };

        if let Some(m) = self.store.best_match(&hash).await {
            if m.distance <= cfg.detection.match_threshold {
                self.on_detection(
                    guild,
                    ctx,
                    &post,
                    &[],
                    bytes,
                    label,
                    DetectionReason::KnownReference {
                        reference: m.filename.clone(),
                        distance: m.distance,
                    },
                )
                .await;
                return true;
            }
        }

        if cfg.flood.enabled {
            if let Some(FloodHit { channels, earlier_messages }) = self
                .flood
                .record_and_check(guild_id, msg.author.id, msg.channel_id, msg.id, hash.primary.clone())
                .await
            {
                // Only the post that crossed the threshold triggered this —
                // clean up the rest of the flood along with it.
                self.on_detection(
                    guild,
                    ctx,
                    &post,
                    &earlier_messages,
                    bytes,
                    label,
                    DetectionReason::CrossChannelFlood { channels },
                )
                .await;
                return true;
            }
        }

        // Last, since it's by far the most expensive check (a tesseract run).
        if let Some(ocr) = &self.ocr {
            match ocr.check(bytes).await {
                Ok(Some(m)) => {
                    self.on_detection(
                        guild,
                        ctx,
                        &post,
                        &[],
                        bytes,
                        label,
                        DetectionReason::ScamText { score: m.score, matched: m.matched },
                    )
                    .await;
                    return true;
                }
                Ok(None) => {}
                Err(e) => tracing::debug!("could not OCR {label}: {e:#}"),
            }
        }

        self.recent.record(post, hash).await;
        false
    }

    /// Adds an image as a reference (bot-wide), then retro-scans the recent
    /// posts that got through before it existed and handles every match like a
    /// normal detection — in whichever server it was posted, with that server's
    /// own settings. Used by `!scam add`, the context menu and the review button.
    pub async fn add_reference(&self, ctx: &Context, bytes: &[u8], ext: &str) -> anyhow::Result<AddedReference> {
        let filename = format!("ref_{}.{}", crate::commands::unique_suffix(), ext);
        self.store.add_from_bytes(&filename, bytes).await?;
        let hash = self.store.hash_bytes(bytes)?;

        let cfg = self.config.snapshot().await;
        let matches = self.recent.take_matches(&hash, cfg.detection.match_threshold).await;
        let retro_matches = matches.len();

        // One scammer usually hit several channels: sanction and log once per
        // (server, author), deleting all of their matching posts.
        let mut groups: Vec<(Post, Vec<(serenity::model::id::ChannelId, serenity::model::id::MessageId)>, u32)> =
            Vec::new();
        for (post, distance) in matches {
            match groups
                .iter_mut()
                .find(|(p, _, _)| p.guild_id == post.guild_id && p.author_id == post.author_id)
            {
                Some((_, others, best)) => {
                    others.push((post.channel_id, post.message_id));
                    *best = (*best).min(distance);
                }
                None => groups.push((post, Vec::new(), distance)),
            }
        }

        for (post, others, distance) in groups {
            let guild = self.guild_settings.get(post.guild_id.get()).await;
            let messages = others.len() + 1;
            self.on_detection(
                &guild,
                ctx,
                &post,
                &others,
                bytes,
                &filename,
                DetectionReason::RetroMatch { reference: filename.clone(), distance, messages },
            )
            .await;
        }

        Ok(AddedReference { filename, retro_matches })
    }

    /// When an author gets flagged, checks their *other* recent image posts in
    /// that server (from `RecentMedia`, within ±`retro_scan_minutes` of the
    /// flagged message) against the flagged image, the references, and — by
    /// re-fetching the message, since only hashes are kept — OCR. Returns the
    /// ones that match, excluding `post` itself and `already`.
    async fn sweep_author(
        &self,
        ctx: &Context,
        post: &Post,
        already: &[(serenity::model::id::ChannelId, serenity::model::id::MessageId)],
        bytes: &[u8],
    ) -> Vec<(serenity::model::id::ChannelId, serenity::model::id::MessageId)> {
        // Bounds the Discord fetches + tesseract runs one detection can cause.
        const MAX_OCR_SWEEP: usize = 10;

        let cfg = self.config.snapshot().await;
        let window = std::time::Duration::from_secs(cfg.detection.retro_scan_minutes * 60);
        if window.is_zero() {
            return Vec::new();
        }
        let threshold = cfg.detection.match_threshold;
        let flagged = self.store.hash_bytes(bytes).ok();

        let mut matched = Vec::new();
        let mut to_ocr = Vec::new();
        for (other, hash) in self
            .recent
            .author_window(post.guild_id, post.author_id, post.message_id, window)
            .await
        {
            let key = (other.channel_id, other.message_id);
            if other.message_id == post.message_id
                || already.iter().any(|(_, m)| *m == other.message_id)
                || matched.contains(&key)
            {
                continue;
            }
            let same_image = flagged.as_ref().is_some_and(|f| f.min_dist(&hash) <= threshold);
            let known = self.store.best_match(&hash).await.is_some_and(|m| m.distance <= threshold);
            if same_image || known {
                to_ocr.retain(|k| *k != key);
                matched.push(key);
            } else if !to_ocr.contains(&key) {
                to_ocr.push(key);
            }
        }

        if let Some(ocr) = &self.ocr {
            for (channel_id, message_id) in to_ocr.into_iter().take(MAX_OCR_SWEEP) {
                let Ok(msg) = channel_id.message(&ctx.http, message_id).await else {
                    continue; // already deleted, or no longer readable
                };
                for (image, _) in self.collect_message_images(&msg).await {
                    if matches!(ocr.check(&image).await, Ok(Some(_))) {
                        matched.push((channel_id, message_id));
                        break;
                    }
                }
            }
        }

        if !matched.is_empty() {
            tracing::info!(
                "sweep: {} other post(s) by {} in guild {} matched around the flagged message",
                matched.len(),
                post.author_id,
                post.guild_id
            );
        }
        matched
    }

    /// Every image in a message — own attachments, forwarded snapshots'
    /// attachments, then allow-listed links (if enabled) — as (bytes, extension),
    /// for adding them as references.
    pub async fn collect_message_images(&self, msg: &Message) -> Vec<(Vec<u8>, String)> {
        let mut images = Vec::new();
        let attachments = msg
            .attachments
            .iter()
            .chain(msg.message_snapshots.iter().flat_map(|s| s.attachments.iter()));
        for att in attachments {
            if !is_image_attachment(att) || att.size > crate::commands::MAX_REFERENCE_BYTES {
                continue;
            }
            match att.download().await {
                Ok(bytes) => images.push((bytes, crate::review::extension_of(&att.filename).to_string())),
                Err(e) => tracing::warn!("could not download {}: {e}", att.filename),
            }
        }

        let cfg = self.config.snapshot().await;
        if cfg.links.enabled {
            let texts = std::iter::once(msg.content.as_str())
                .chain(msg.message_snapshots.iter().map(|s| s.content.as_str()));
            for text in texts {
                for url in self.links.extract_urls(text) {
                    match self.links.fetch_image_bytes(&url).await {
                        Ok(Some(bytes)) => images.push((bytes, "png".to_string())),
                        Ok(None) => {}
                        Err(e) => tracing::debug!("could not fetch linked image {url}: {e:#}"),
                    }
                }
            }
        }
        images
    }

    /// Deletes the post (plus `others`, other posts of the same author that are
    /// part of the same detection), sanctions the author per the guild's
    /// settings, and logs it with review buttons.
    #[allow(clippy::too_many_arguments)]
    async fn on_detection(
        &self,
        guild: &GuildConfig,
        ctx: &Context,
        post: &Post,
        others: &[(serenity::model::id::ChannelId, serenity::model::id::MessageId)],
        bytes: &[u8],
        filename: &str,
        reason: DetectionReason,
    ) {
        tracing::info!(
            "detection: guild={} author={} channel={} reason={}",
            post.guild_id,
            post.author_id,
            post.channel_id,
            reason.description()
        );

        // The same account's other images around that time (compromised
        // accounts rarely post just one), checked against this image, the
        // references and OCR — matches are handled as part of this detection.
        let swept = self.sweep_author(ctx, post, others, bytes).await;
        let others: Vec<_> = others.iter().copied().chain(swept.iter().copied()).collect();
        let others = others.as_slice();

        // The earlier posts of a flood were recorded as "recent, harmless" before
        // the flood was detected — make sure a retro-scan never acts on them again.
        let handled: Vec<_> = std::iter::once(post.message_id).chain(others.iter().map(|(_, m)| *m)).collect();
        self.recent.forget(&handled).await;

        let action = guild.action;
        let mut action_taken = "No action (log-only mode)".to_string();

        if action != Action::LogOnly {
            let mut deleted = 0;
            let targets = std::iter::once((post.channel_id, post.message_id)).chain(others.iter().copied());
            for (channel_id, message_id) in targets {
                match channel_id.delete_message(&ctx.http, message_id).await {
                    Ok(()) => deleted += 1,
                    Err(e) => tracing::warn!("could not delete message {message_id} in {channel_id}: {e}"),
                }
            }
            if deleted == 1 {
                action_taken = "Message deleted".to_string();
            } else if deleted > 1 {
                action_taken = format!("{deleted} messages deleted");
            }
            if !swept.is_empty() {
                action_taken.push_str(&format!(
                    " (incl. {} other post(s) by this author found around that time)",
                    swept.len()
                ));
            }
        }

        if matches!(action, Action::DeleteTimeout | Action::DeleteKick | Action::DeleteBan) {
            match post.guild_id.member(ctx, post.author_id).await {
                Ok(mut member) => {
                    let reason_str = "Account likely compromised: scam automatically detected";
                    let outcome = match action {
                        Action::DeleteTimeout => {
                            let now = SystemTime::now()
                                .duration_since(UNIX_EPOCH)
                                .unwrap()
                                .as_secs() as i64;
                            let until = now + (guild.timeout_minutes as i64) * 60;
                            match Timestamp::from_unix_timestamp(until) {
                                Ok(ts) => member
                                    .disable_communication_until_datetime(ctx, ts)
                                    .await
                                    .map(|()| format!("timeout {} min", guild.timeout_minutes))
                                    .map_err(|e| e.to_string()),
                                Err(e) => Err(e.to_string()),
                            }
                        }
                        Action::DeleteKick => member
                            .kick_with_reason(ctx, reason_str)
                            .await
                            .map(|()| "member kicked".to_string())
                            .map_err(|e| e.to_string()),
                        Action::DeleteBan => member
                            .ban_with_reason(ctx, 1, reason_str)
                            .await
                            .map(|()| "member banned".to_string())
                            .map_err(|e| e.to_string()),
                        _ => unreachable!(),
                    };
                    match outcome {
                        Ok(desc) => action_taken = format!("{action_taken} + {desc}"),
                        Err(e) => {
                            tracing::warn!("could not sanction member: {e}");
                            action_taken = format!("{action_taken} (sanction failed: {e})");
                        }
                    }
                }
                Err(e) => tracing::warn!("could not fetch member: {e}"),
            }
        }

        self.send_log(guild, ctx, post, bytes, filename, &reason, &action_taken)
            .await;
    }

    #[allow(clippy::too_many_arguments)]
    async fn send_log(
        &self,
        guild: &GuildConfig,
        ctx: &Context,
        post: &Post,
        bytes: &[u8],
        filename: &str,
        reason: &DetectionReason,
        action_taken: &str,
    ) {
        let log_channel_id = guild.log_channel_id;
        if log_channel_id == 0 {
            return;
        }

        let safe_name = sanitize_filename(filename);
        let embed = CreateEmbed::new()
            .title(reason.title())
            .description(reason.description())
            .colour(Colour::from_rgb(220, 50, 47))
            .field("Author", format!("<@{}> (`{}`)", post.author_id, post.author_id), true)
            .field("Channel", format!("<#{}>", post.channel_id), true)
            .field("Action taken", action_taken, false)
            .attachment(&safe_name)
            .timestamp(Timestamp::now());

        let attachment = CreateAttachment::bytes(bytes.to_vec(), safe_name);
        let builder = CreateMessage::new()
            .embed(embed)
            .add_file(attachment)
            .components(reason.review_buttons(post.author_id));

        if let Err(e) = serenity::model::id::ChannelId::new(log_channel_id)
            .send_message(&ctx.http, builder)
            .await
        {
            tracing::warn!("could not send moderation log: {e}");
        }
    }
}

fn is_image_attachment(attachment: &serenity::model::channel::Attachment) -> bool {
    attachment
        .content_type
        .as_deref()
        .map(|c| c.starts_with("image/"))
        .unwrap_or_else(|| {
            let lower = attachment.filename.to_lowercase();
            [".png", ".jpg", ".jpeg", ".webp", ".gif", ".bmp"]
                .iter()
                .any(|ext| lower.ends_with(ext))
        })
}

fn sanitize_filename(name: &str) -> String {
    let cleaned: String = name
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-' { c } else { '_' })
        .collect();
    if cleaned.is_empty() {
        "evidence.png".to_string()
    } else {
        cleaned
    }
}
