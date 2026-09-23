use anyhow::{Context as _, Result};
use serenity::all::*;

use crate::config::{Action, GuildConfig};
use crate::handler::Handler;

/// Name of the message context-menu command (right click a message → Apps).
pub const ADD_REFERENCE_MENU: &str = "Add to scam references";

/// Prefix of every button `custom_id` this bot creates, so `interaction_create`
/// can route them here. The rest encodes everything the click needs (no
/// server-side state), so buttons keep working across restarts:
///   `antiscam:add:<user_id>`             add the log's evidence image as a reference
///   `antiscam:dismiss:<user_id>`         false positive: lift the author's timeout
///   `antiscam:rmref:<user_id>:<file>`    false positive: remove that reference too
/// `user_id` is the flagged author (0 = none, e.g. a manual add).
const BUTTON_PREFIX: &str = "antiscam:";

pub fn is_review_button(custom_id: &str) -> bool {
    custom_id.starts_with(BUTTON_PREFIX)
}

pub fn build_add_reference_menu() -> CreateCommand {
    CreateCommand::new(ADD_REFERENCE_MENU)
        .kind(CommandType::Message)
        .default_member_permissions(Permissions::MANAGE_MESSAGES)
}

/// Buttons under a detection whose image is *not* a reference yet (flood, OCR):
/// confirm it (→ becomes a reference, and retro-scans recent posts) or dismiss it.
pub fn unconfirmed_detection_buttons(author: UserId) -> Vec<CreateActionRow> {
    vec![CreateActionRow::Buttons(vec![
        CreateButton::new(format!("{BUTTON_PREFIX}add:{author}"))
            .label("➕ Scam: add to references")
            .style(ButtonStyle::Success),
        CreateButton::new(format!("{BUTTON_PREFIX}dismiss:{author}"))
            .label("✖ False positive")
            .style(ButtonStyle::Secondary),
    ])]
}

/// Button under a detection (or manual add) caused by an existing reference:
/// a false positive there means the reference itself is bad.
pub fn reference_buttons(author: Option<UserId>, reference: &str) -> Vec<CreateActionRow> {
    let custom_id = format!("{BUTTON_PREFIX}rmref:{}:{reference}", author.map_or(0, |u| u.get()));
    // Discord caps custom_id at 100 chars; a longer (hand-named) reference just
    // gets no button — `!scam remove` still works for it.
    if custom_id.len() > 100 {
        return Vec::new();
    }
    vec![CreateActionRow::Buttons(vec![CreateButton::new(custom_id)
        .label(format!("✖ False positive: remove {}", truncate(reference, 40)))
        .style(ButtonStyle::Danger)])]
}

/// Same check as `!scam add/remove` (reference management), for an interaction's
/// member: one of the guild's mod roles if any are set, else Manage Messages.
/// Defense in depth on top of the command's `default_member_permissions` — and
/// the *only* gate for buttons, which anyone who can see the log channel can click.
fn can_manage_references(guild: &GuildConfig, member: Option<&Member>) -> bool {
    let Some(member) = member else {
        return false;
    };
    if !guild.mod_role_ids.is_empty() {
        return member.roles.iter().any(|r| guild.mod_role_ids.contains(&r.get()));
    }
    member.permissions.map(|p| p.manage_messages()).unwrap_or(false)
}

const NOT_ALLOWED: &str = "You need the **Manage Messages** permission (or one of this server's \
                           mod roles) to manage scam references.";

pub async fn handle_add_reference_menu(
    handler: &Handler,
    ctx: &Context,
    command: &CommandInteraction,
) -> Result<()> {
    let Some(guild_id) = command.guild_id else {
        return reply_ephemeral(ctx, command, "This only works in a server.").await;
    };
    let guild = handler.guild_settings.get(guild_id.get()).await;
    if !can_manage_references(&guild, command.member.as_deref()) {
        return reply_ephemeral(ctx, command, NOT_ALLOWED).await;
    }
    let Some(ResolvedTarget::Message(target)) = command.data.target() else {
        return reply_ephemeral(ctx, command, "Could not read the target message.").await;
    };

    // Downloads + hashing + the retro-scan's moderation calls easily exceed the
    // 3 s Discord gives for a first response.
    command.defer_ephemeral(&ctx.http).await?;

    let images = handler.collect_message_images(target).await;
    if images.is_empty() {
        command
            .edit_response(
                &ctx.http,
                EditInteractionResponse::new()
                    .content("No image found in that message (attachments, forwarded images or allow-listed links)."),
            )
            .await?;
        return Ok(());
    }

    let mut added = Vec::new();
    let mut retro_total = 0;
    let mut failures = 0;
    for (bytes, ext) in &images {
        match handler.add_reference(ctx, bytes, ext).await {
            Ok(outcome) => {
                retro_total += outcome.retro_matches;
                added.push((outcome.filename, bytes));
            }
            Err(e) => {
                tracing::warn!("could not add reference from context menu: {e:#}");
                failures += 1;
            }
        }
    }

    tracing::info!(
        "{} reference(s) added via context menu by {} in guild {guild_id} (retro-scan: {retro_total} match(es))",
        added.len(),
        command.user.id
    );

    if !added.is_empty() {
        post_manual_add_log(ctx, &guild, command.user.id, target, &added, retro_total).await;
    }

    let mut text = format!("Added {} reference(s).", added.len());
    if failures > 0 {
        text.push_str(&format!(" {failures} image(s) could not be added (see logs)."));
    }
    text.push_str(&retro_summary(retro_total));
    command.edit_response(&ctx.http, EditInteractionResponse::new().content(text)).await?;
    Ok(())
}

/// Posts a record of a manual add to the guild's log channel, with the image(s)
/// and an undo button per reference — so every addition gets a second look.
async fn post_manual_add_log(
    ctx: &Context,
    guild: &GuildConfig,
    moderator: UserId,
    target: &Message,
    added: &[(String, &Vec<u8>)],
    retro_total: usize,
) {
    if guild.log_channel_id == 0 {
        return;
    }
    let mut builder = CreateMessage::new();
    let mut rows = Vec::new();
    for (i, (filename, bytes)) in added.iter().enumerate().take(10) {
        let mut embed = CreateEmbed::new()
            .colour(Colour::from_rgb(88, 101, 242))
            .attachment(filename);
        if i == 0 {
            embed = embed
                .title("➕ Scam reference added manually")
                .field("Added by", format!("<@{moderator}>"), true)
                .field("From", format!("{} by <@{}>", target.link(), target.author.id), true)
                .field("Retro-scan", retro_summary(retro_total).trim().to_string(), false)
                .timestamp(Timestamp::now());
        }
        builder = builder
            .add_embed(embed)
            .add_file(CreateAttachment::bytes(bytes.to_vec(), filename.clone()));
        rows.extend(reference_buttons(None, filename));
    }
    rows.truncate(5);
    builder = builder.components(rows);

    if let Err(e) = ChannelId::new(guild.log_channel_id).send_message(&ctx.http, builder).await {
        tracing::warn!("could not post manual-add log: {e}");
    }
}

pub async fn handle_review_button(
    handler: &Handler,
    ctx: &Context,
    component: &ComponentInteraction,
) -> Result<()> {
    let Some(guild_id) = component.guild_id else {
        return Ok(());
    };
    let guild = handler.guild_settings.get(guild_id.get()).await;
    if !can_manage_references(&guild, component.member.as_ref()) {
        component
            .create_response(
                &ctx.http,
                CreateInteractionResponse::Message(
                    CreateInteractionResponseMessage::new().ephemeral(true).content(NOT_ALLOWED),
                ),
            )
            .await?;
        return Ok(());
    }

    let rest = &component.data.custom_id[BUTTON_PREFIX.len()..];
    let mut parts = rest.splitn(3, ':');
    let kind = parts.next().unwrap_or("");
    let author = parts.next().and_then(|s| s.parse::<u64>().ok()).filter(|&id| id != 0).map(UserId::new);
    let reference = parts.next();

    component.defer(&ctx.http).await?;
    let moderator = component.user.id;

    let outcome = match kind {
        "add" => confirm_scam(handler, ctx, component).await,
        "dismiss" => Ok(format!(
            "✖ False positive (<@{moderator}>){}",
            lift_timeout(ctx, &guild, guild_id, author).await
        )),
        "rmref" => {
            let reference = reference.unwrap_or("");
            let removed = match handler.store.remove(reference).await {
                Ok(true) => format!("reference `{reference}` removed"),
                Ok(false) => format!("reference `{reference}` was already gone"),
                Err(e) => {
                    tracing::warn!("could not remove reference {reference}: {e:#}");
                    format!("could not remove reference `{reference}`")
                }
            };
            tracing::info!("reference {reference} removed via button by {moderator} in guild {guild_id}");
            Ok(format!(
                "✖ False positive (<@{moderator}>): {removed}{}",
                lift_timeout(ctx, &guild, guild_id, author).await
            ))
        }
        _ => Ok("Unknown button.".to_string()),
    };

    let review = match outcome {
        Ok(text) => text,
        Err(e) => {
            tracing::warn!("review button {kind} failed: {e:#}");
            // Keep the buttons so it can be retried.
            component
                .create_followup(
                    &ctx.http,
                    CreateInteractionResponseFollowup::new()
                        .ephemeral(true)
                        .content(format!("Something went wrong: {e}")),
                )
                .await?;
            return Ok(());
        }
    };

    // Record the review on the log message itself and drop its buttons, so it
    // can't be actioned twice and the channel shows what was decided.
    // Re-point each embed's image at its attachment (`attachment://`) rather than
    // the CDN URL it comes back with, or Discord shows the image twice.
    let attachments = &component.message.attachments;
    let mut embeds: Vec<CreateEmbed> = component
        .message
        .embeds
        .iter()
        .cloned()
        .map(|embed| {
            let attached = embed
                .image
                .as_ref()
                .and_then(|img| attachments.iter().find(|a| a.url == img.url || a.proxy_url == img.url))
                .map(|a| a.filename.clone());
            let builder = CreateEmbed::from(embed);
            match attached {
                Some(filename) => builder.attachment(filename),
                None => builder,
            }
        })
        .collect();
    if let Some(first) = embeds.first_mut() {
        *first = first.clone().field("Review", review, false);
    }
    component
        .edit_response(&ctx.http, EditInteractionResponse::new().embeds(embeds).components(Vec::new()))
        .await?;
    Ok(())
}

/// "➕ Scam: add to references" — the log message's own evidence attachment
/// becomes a reference (then retro-scans recent posts, like any add).
async fn confirm_scam(handler: &Handler, ctx: &Context, component: &ComponentInteraction) -> Result<String> {
    let attachment = component
        .message
        .attachments
        .first()
        .context("this log message has no image attached")?;
    if attachment.size > crate::commands::MAX_REFERENCE_BYTES {
        anyhow::bail!("image is over the reference size limit");
    }
    let bytes = attachment.download().await.context("could not download the evidence image")?;
    let outcome = handler.add_reference(ctx, &bytes, extension_of(&attachment.filename)).await?;
    tracing::info!(
        "reference {} added via button by {} (retro-scan: {} match(es))",
        outcome.filename,
        component.user.id,
        outcome.retro_matches
    );
    Ok(format!(
        "✅ Confirmed scam (<@{}>): added as `{}`.{}",
        component.user.id,
        outcome.filename,
        retro_summary(outcome.retro_matches)
    ))
}

/// Only undoes a timeout — a kick or ban can't be silently reverted, and the
/// author may simply no longer be in the server.
async fn lift_timeout(ctx: &Context, guild: &GuildConfig, guild_id: GuildId, author: Option<UserId>) -> String {
    let Some(author) = author else {
        return String::new();
    };
    if guild.action != Action::DeleteTimeout {
        return String::new();
    }
    match guild_id
        .edit_member(&ctx.http, author, EditMember::new().enable_communication())
        .await
    {
        Ok(_) => format!(", timeout of <@{author}> lifted"),
        Err(e) => {
            tracing::warn!("could not lift timeout of {author}: {e}");
            format!(", could not lift the timeout of <@{author}>")
        }
    }
}

fn retro_summary(matches: usize) -> String {
    match matches {
        0 => " Retro-scan: no recent post matched.".to_string(),
        n => format!(" Retro-scan: {n} recent post(s) matched and were handled per each server's settings."),
    }
}

/// Extension to save a reference under — only a short alphanumeric one from the
/// original filename, since the filename itself comes from user input.
pub fn extension_of(filename: &str) -> &str {
    std::path::Path::new(filename)
        .extension()
        .and_then(|e| e.to_str())
        .filter(|e| !e.is_empty() && e.len() <= 5 && e.chars().all(|c| c.is_ascii_alphanumeric()))
        .unwrap_or("png")
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        format!("{}…", s.chars().take(max - 1).collect::<String>())
    }
}

async fn reply_ephemeral(ctx: &Context, command: &CommandInteraction, text: &str) -> Result<()> {
    command
        .create_response(
            &ctx.http,
            CreateInteractionResponse::Message(
                CreateInteractionResponseMessage::new().ephemeral(true).content(text),
            ),
        )
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extension_is_sanitized() {
        assert_eq!(extension_of("image.jpg"), "jpg");
        assert_eq!(extension_of("no_extension"), "png");
        assert_eq!(extension_of("evil.j/../pg"), "png");
        assert_eq!(extension_of("weird.verylongext"), "png");
    }

    #[test]
    fn reference_button_encodes_author_and_file() {
        let rows = reference_buttons(Some(UserId::new(42)), "ref_abc.jpg");
        let json = serde_json::to_string(&rows).unwrap();
        assert!(json.contains("antiscam:rmref:42:ref_abc.jpg"), "{json}");
        assert!(reference_buttons(None, &"x".repeat(100)).is_empty());
    }
}
