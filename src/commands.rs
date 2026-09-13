use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Result;
use serenity::model::channel::Message;
use serenity::prelude::*;

use crate::handler::Handler;

pub async fn handle_command(handler: &Handler, ctx: &Context, msg: &Message, rest: &str) -> Result<()> {
    if !is_authorized(handler, ctx, msg).await {
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

async fn is_authorized(handler: &Handler, ctx: &Context, msg: &Message) -> bool {
    let Ok(member) = msg.member(ctx).await else {
        return false;
    };
    if !handler.config.bot.mod_role_ids.is_empty() {
        return member
            .roles
            .iter()
            .any(|r| handler.config.bot.mod_role_ids.contains(&r.get()));
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
    for att in &msg.attachments {
        let bytes = match att.download().await {
            Ok(b) => b,
            Err(e) => {
                tracing::warn!("could not download {}: {e}", att.filename);
                continue;
            }
        };
        let ext = std::path::Path::new(&att.filename)
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("png");
        let filename = format!("ref_{}.{}", unique_suffix(), ext);
        if let Err(e) = handler.store.add_from_bytes(&filename, &bytes).await {
            tracing::warn!("could not add reference {filename}: {e:#}");
            continue;
        }
        added += 1;
    }

    msg.channel_id
        .say(
            &ctx.http,
            format!(
                "{added} reference image(s) added. Total: {}",
                handler.store.len().await
            ),
        )
        .await?;
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

fn unique_suffix() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    format!("{nanos:x}")
}
