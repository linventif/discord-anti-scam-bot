use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use serenity::async_trait;
use serenity::builder::{CreateAttachment, CreateEmbed, CreateMessage};
use serenity::model::channel::Message;
use serenity::model::colour::Colour;
use serenity::model::gateway::Ready;
use serenity::model::timestamp::Timestamp;
use serenity::prelude::*;

use crate::config::{Action, Config};
use crate::flood::FloodDetector;
use crate::hashstore::ReferenceStore;
use crate::linkimage::LinkImageFetcher;

pub struct Handler {
    pub config: Config,
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
    async fn ready(&self, _ctx: Context, ready: Ready) {
        tracing::info!("Logged in as {}", ready.user.name);
        tracing::info!("{} reference image(s) in memory", self.store.len().await);
    }

    async fn message(&self, ctx: Context, msg: Message) {
        if msg.author.bot || msg.guild_id.is_none() {
            return;
        }

        if let Some(rest) = msg.content.strip_prefix(&self.config.bot.prefix) {
            if let Err(e) = crate::commands::handle_command(self, &ctx, &msg, rest.trim()).await {
                tracing::warn!("error while handling command: {e:#}");
            }
            return;
        }

        if msg.attachments.is_empty() && !self.config.links.enabled {
            return;
        }

        if self
            .config
            .moderation
            .exempt_channel_ids
            .contains(&msg.channel_id.get())
        {
            return;
        }

        if let Ok(member) = msg.member(&ctx).await {
            let exempt = member
                .roles
                .iter()
                .any(|r| self.config.moderation.exempt_role_ids.contains(&r.get()));
            if exempt {
                return;
            }
        }

        for attachment in &msg.attachments {
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

            if self.evaluate_image(&ctx, &msg, &bytes, &attachment.filename).await {
                return;
            }
        }

        if self.config.links.enabled {
            for url in self.links.extract_urls(&msg.content) {
                let bytes = match self.links.fetch_image_bytes(&url).await {
                    Ok(Some(b)) => b,
                    Ok(None) => continue,
                    Err(e) => {
                        tracing::debug!("could not fetch linked image {url}: {e:#}");
                        continue;
                    }
                };

                if self.evaluate_image(&ctx, &msg, &bytes, &url).await {
                    return;
                }
            }
        }
    }
}

impl Handler {
    /// Hashes and checks one image (from an attachment or a fetched link) against
    /// known references and flood activity. Returns `true` if a detection fired
    /// (and was handled), so the caller can stop looking at further images in the
    /// same message.
    async fn evaluate_image(&self, ctx: &Context, msg: &Message, bytes: &[u8], label: &str) -> bool {
        let hash = match self.store.hash_bytes(bytes) {
            Ok(h) => h,
            Err(e) => {
                tracing::debug!("could not hash {label}: {e}");
                return false;
            }
        };

        if let Some(m) = self.store.best_match(&hash).await {
            if m.distance <= self.config.detection.match_threshold {
                self.on_detection(
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

        if self.config.flood.enabled {
            if let Some(channels) = self
                .flood
                .record_and_check(msg.author.id, msg.channel_id, hash.primary)
                .await
            {
                self.on_detection(
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

        let action = self.config.moderation.action;
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
                            let until = now + (self.config.moderation.timeout_minutes as i64) * 60;
                            match Timestamp::from_unix_timestamp(until) {
                                Ok(ts) => member
                                    .disable_communication_until_datetime(ctx, ts)
                                    .await
                                    .map(|()| {
                                        format!(
                                            "Message deleted + timeout {} min",
                                            self.config.moderation.timeout_minutes
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

        self.send_log(ctx, msg, bytes, filename, &reason, &action_taken)
            .await;
    }

    async fn send_log(
        &self,
        ctx: &Context,
        msg: &Message,
        bytes: &[u8],
        filename: &str,
        reason: &DetectionReason,
        action_taken: &str,
    ) {
        let log_channel_id = self.config.bot.log_channel_id;
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
