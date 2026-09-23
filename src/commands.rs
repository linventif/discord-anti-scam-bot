use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Result;
use serenity::model::channel::Message;
use serenity::prelude::*;

use crate::config::GuildConfig;
use crate::handler::Handler;

/// Reference images are shared across every guild the bot is in (by design —
/// see docs/ARCHITECTURE.md), which means a mod-role holder in *any one* of
/// them can add to a data set every other guild pays the storage and
/// per-message hashing cost of. Discord's own attachment size limit already
/// bounds this loosely (and inconsistently, since it scales with a server's
/// boost level), so enforce a tighter, consistent cap here too rather than
/// relying on that alone.
pub const MAX_REFERENCE_BYTES: u32 = 15 * 1024 * 1024;

pub async fn handle_command(
    handler: &Handler,
    guild: &GuildConfig,
    ctx: &Context,
    msg: &Message,
    rest: &str,
) -> Result<()> {
    if !is_authorized(guild, ctx, msg).await {
        return Ok(());
    }

    let mut parts = rest.split_whitespace();
    match parts.next().unwrap_or("") {
        "add" => cmd_add(handler, ctx, msg).await?,
        "list" => cmd_list(handler, ctx, msg).await?,
        "remove" => cmd_remove(handler, ctx, msg, parts.next()).await?,
        _ => {
            msg.channel_id
                .say(
                    &ctx.http,
                    "Available commands:\n\
                     `!scam add` (with one or more attached images) — add scam references\n\
                     `!scam list` — list known references\n\
                     `!scam remove <file>` — remove a reference",
                )
                .await?;
        }
    }
    Ok(())
}

async fn is_authorized(guild: &GuildConfig, ctx: &Context, msg: &Message) -> bool {
    let Ok(member) = msg.member(ctx).await else {
        return false;
    };
    if !guild.mod_role_ids.is_empty() {
        return member
            .roles
            .iter()
            .any(|r| guild.mod_role_ids.contains(&r.get()));
    }
    // Role-based check (ignores channel overwrites): good enough for a global
    // moderation command, and avoids having to resolve the GuildChannel.
    #[allow(deprecated)]
    member
        .permissions(&ctx.cache)
        .map(|p| p.manage_messages())
        .unwrap_or(false)
}

async fn cmd_add(handler: &Handler, ctx: &Context, msg: &Message) -> Result<()> {
    if msg.attachments.is_empty() {
        msg.channel_id
            .say(&ctx.http, "Attach one or more images to your `!scam add` command.")
            .await?;
        return Ok(());
    }

    let mut added = 0usize;
    let mut retro = 0usize;
    let mut too_large = 0usize;
    for att in &msg.attachments {
        if att.size > MAX_REFERENCE_BYTES {
            too_large += 1;
            continue;
        }

        let bytes = match att.download().await {
            Ok(b) => b,
            Err(e) => {
                tracing::warn!("could not download {}: {e}", att.filename);
                continue;
            }
        };
        match handler.add_reference(ctx, &bytes, crate::review::extension_of(&att.filename)).await {
            Ok(outcome) => {
                added += 1;
                retro += outcome.retro_matches;
            }
            Err(e) => tracing::warn!("could not add reference from {}: {e:#}", att.filename),
        }
    }

    let mut reply = format!(
        "{added} reference image(s) added. Total: {}",
        handler.store.len().await
    );
    if retro > 0 {
        reply.push_str(&format!("\nRetro-scan: {retro} recent post(s) matched and were handled."));
    }
    if too_large > 0 {
        let max_mb = MAX_REFERENCE_BYTES / (1024 * 1024);
        reply.push_str(&format!(
            "\n{too_large} image(s) skipped: over the {max_mb} MiB reference size limit."
        ));
    }
    msg.channel_id.say(&ctx.http, reply).await?;
    Ok(())
}

async fn cmd_list(handler: &Handler, ctx: &Context, msg: &Message) -> Result<()> {
    let list = handler.store.list().await;
    if list.is_empty() {
        msg.channel_id.say(&ctx.http, "No reference stored yet.").await?;
        return Ok(());
    }
    let text = list.join("\n");
    msg.channel_id
        .say(&ctx.http, format!("**{} reference(s):**\n```\n{text}\n```", list.len()))
        .await?;
    Ok(())
}

async fn cmd_remove(handler: &Handler, ctx: &Context, msg: &Message, name: Option<&str>) -> Result<()> {
    let Some(name) = name else {
        msg.channel_id
            .say(&ctx.http, "Usage: `!scam remove <filename>` (see `!scam list`)")
            .await?;
        return Ok(());
    };
    if handler.store.remove(name).await? {
        msg.channel_id.say(&ctx.http, format!("Reference `{name}` removed.")).await?;
    } else {
        msg.channel_id.say(&ctx.http, format!("No reference named `{name}`.")).await?;
    }
    Ok(())
}

pub fn unique_suffix() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    format!("{nanos:x}")
}
