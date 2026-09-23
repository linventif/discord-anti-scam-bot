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

pub struct Handler {
    pub config: Arc<ConfigStore>,
    pub guild_settings: Arc<GuildSettingsStore>,
    pub store: Arc<ReferenceStore>,
    pub flood: Arc<FloodDetector>,
    pub links: LinkImageFetcher,
}

enum DetectionReason {
    KnownReference { reference: String, distance: u32 },
    CrossChannelFlood { channels: usize },
}

impl DetectionReason {
    fn title(&self) -> &'static str {
        match self {
            DetectionReason::KnownReference { .. } => "🚨 Image matches a known scam",
            DetectionReason::CrossChannelFlood { .. } => "🚨 Same image posted across multiple channels",
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
        let command = crate::slashconfig::build_config_command();
        match serenity::model::application::Command::set_global_commands(&ctx.http, vec![command]).await {
            Ok(_) => tracing::info!("/config command registered globally"),
            Err(e) => tracing::warn!("could not register /config command globally: {e}"),
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
            let is_image = attachment
                .content_type
                .as_deref()
                .map(|c| c.starts_with("image/"))
                .unwrap_or_else(|| {
                    let lower = attachment.filename.to_lowercase();
                    [".png", ".jpg", ".jpeg", ".webp", ".gif", ".bmp"]
                        .iter()
                        .any(|ext| lower.ends_with(ext))
                });
            if !is_image {
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

        if let Some(m) = self.store.best_match(&hash).await {
            if m.distance <= cfg.detection.match_threshold {
                self.on_detection(
                    guild,
                    ctx,
                    msg,
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
                .record_and_check(guild_id, msg.author.id, msg.channel_id, msg.id, hash.primary)
                .await
            {
                // Only the post that crossed the threshold goes through
                // on_detection — clean up the rest of the flood as well.
                if guild.action != Action::LogOnly {
                    for (channel_id, message_id) in earlier_messages {
                        if let Err(e) = channel_id.delete_message(&ctx.http, message_id).await {
                            tracing::warn!(
                                "could not delete earlier flood message {message_id} in {channel_id}: {e}"
                            );
                        }
                    }
                }

                self.on_detection(
                    guild,
                    ctx,
                    msg,
                    bytes,
                    label,
                    DetectionReason::CrossChannelFlood { channels },
                )
                .await;
                return true;
            }
        }

        false
    }

    async fn on_detection(
        &self,
        guild: &GuildConfig,
        ctx: &Context,
        msg: &Message,
        bytes: &[u8],
        filename: &str,
        reason: DetectionReason,
    ) {
        tracing::info!(
            "detection: author={} channel={} reason={}",
            msg.author.id,
            msg.channel_id,
            reason.description()
        );

        let action = guild.action;
        let mut action_taken = "No action (log-only mode)".to_string();

        if action != Action::LogOnly {
            match msg.delete(&ctx.http).await {
                Ok(()) => action_taken = "Message deleted".to_string(),
                Err(e) => tracing::warn!("could not delete message: {e}"),
            }
        }

        if matches!(action, Action::DeleteTimeout | Action::DeleteKick | Action::DeleteBan) {
            match msg.member(ctx).await {
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
                                    .map(|()| {
                                        format!(
                                            "Message deleted + timeout {} min",
                                            guild.timeout_minutes
                                        )
                                    })
                                    .map_err(|e| e.to_string()),
                                Err(e) => Err(e.to_string()),
                            }
                        }
                        Action::DeleteKick => member
                            .kick_with_reason(ctx, reason_str)
                            .await
                            .map(|()| "Message deleted + member kicked".to_string())
                            .map_err(|e| e.to_string()),
                        Action::DeleteBan => member
                            .ban_with_reason(ctx, 1, reason_str)
                            .await
                            .map(|()| "Message deleted + member banned".to_string())
                            .map_err(|e| e.to_string()),
                        _ => unreachable!(),
                    };
                    match outcome {
                        Ok(desc) => action_taken = desc,
                        Err(e) => tracing::warn!("could not sanction member: {e}"),
                    }
                }
                Err(e) => tracing::warn!("could not fetch member: {e}"),
            }
        }

        self.send_log(guild, ctx, msg, bytes, filename, &reason, &action_taken)
            .await;
    }

    async fn send_log(
        &self,
        guild: &GuildConfig,
        ctx: &Context,
        msg: &Message,
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
            .field("Author", format!("<@{}> (`{}`)", msg.author.id, msg.author.id), true)
            .field("Channel", format!("<#{}>", msg.channel_id), true)
            .field("Action taken", action_taken, false)
            .attachment(&safe_name)
            .timestamp(Timestamp::now());

        let attachment = CreateAttachment::bytes(bytes.to_vec(), safe_name);
        let builder = CreateMessage::new().embed(embed).add_file(attachment);

        if let Err(e) = serenity::model::id::ChannelId::new(log_channel_id)
            .send_message(&ctx.http, builder)
            .await
        {
            tracing::warn!("could not send moderation log: {e}");
        }
    }
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
