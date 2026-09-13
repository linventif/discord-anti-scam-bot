use anyhow::Result;
use serenity::all::*;

use crate::config::{Action, Config};
use crate::handler::Handler;

/// Builds the `/config` command tree: flat subcommands for single-value settings,
/// and a subcommand group (`add`/`remove`) for each of the three role/channel
/// lists. Role options and `action` get Discord's native picker/choice UI; the log
/// channel uses autocomplete instead of the native channel picker so we can only
/// ever suggest channels the bot can actually post in (see `handle_config_autocomplete`).
pub fn build_config_command() -> CreateCommand {
    CreateCommand::new("config")
        .description("View or change discord-anti-scam-bot settings for this server")
        .default_member_permissions(Permissions::ADMINISTRATOR)
        .add_option(
            CreateCommandOption::new(
                CommandOptionType::SubCommand,
                "log-channel",
                "Channel where detection evidence gets posted",
            )
            .add_sub_option(
                CreateCommandOption::new(
                    CommandOptionType::String,
                    "channel",
                    "Only channels I can actually post in are suggested",
                )
                .required(true)
                .set_autocomplete(true),
            ),
        )
        .add_option(
            CreateCommandOption::new(
                CommandOptionType::SubCommand,
                "action",
                "Sanction applied when a scam is detected",
            )
            .add_sub_option(
                CreateCommandOption::new(CommandOptionType::String, "value", "Action")
                    .required(true)
                    .add_string_choice("Log only, no sanction", Action::LogOnly.as_toml_str())
                    .add_string_choice("Delete the message only", Action::DeleteOnly.as_toml_str())
                    .add_string_choice(
                        "Delete + timeout (recommended)",
                        Action::DeleteTimeout.as_toml_str(),
                    )
                    .add_string_choice("Delete + kick", Action::DeleteKick.as_toml_str())
                    .add_string_choice("Delete + ban", Action::DeleteBan.as_toml_str()),
            ),
        )
        .add_option(
            CreateCommandOption::new(
                CommandOptionType::SubCommand,
                "timeout-minutes",
                "Timeout duration used by the delete_timeout action",
            )
            .add_sub_option(
                CreateCommandOption::new(
                    CommandOptionType::Integer,
                    "minutes",
                    "Duration in minutes (max 40320 = 28 days)",
                )
                .required(true)
                .min_int_value(1)
                .max_int_value(40320),
            ),
        )
        .add_option(CreateCommandOption::new(
            CommandOptionType::SubCommand,
            "show",
            "Show the current settings",
        ))
        .add_option(role_group(
            "mod-role",
            "Roles allowed to manage this bot's settings",
        ))
        .add_option(role_group("exempt-role", "Roles exempt from detection"))
        .add_option(channel_group(
            "exempt-channel",
            "Channels exempt from detection",
        ))
}

fn role_group(name: &'static str, description: &'static str) -> CreateCommandOption {
    CreateCommandOption::new(CommandOptionType::SubCommandGroup, name, description)
        .add_sub_option(
            CreateCommandOption::new(CommandOptionType::SubCommand, "add", "Add a role")
                .add_sub_option(
                    CreateCommandOption::new(CommandOptionType::Role, "role", "Role").required(true),
                ),
        )
        .add_sub_option(
            CreateCommandOption::new(CommandOptionType::SubCommand, "remove", "Remove a role")
                .add_sub_option(
                    CreateCommandOption::new(CommandOptionType::Role, "role", "Role").required(true),
                ),
        )
}

fn channel_group(name: &'static str, description: &'static str) -> CreateCommandOption {
    CreateCommandOption::new(CommandOptionType::SubCommandGroup, name, description)
        .add_sub_option(
            CreateCommandOption::new(CommandOptionType::SubCommand, "add", "Add a channel")
                .add_sub_option(
                    CreateCommandOption::new(CommandOptionType::Channel, "channel", "Channel")
                        .required(true),
                ),
        )
        .add_sub_option(
            CreateCommandOption::new(CommandOptionType::SubCommand, "remove", "Remove a channel")
                .add_sub_option(
                    CreateCommandOption::new(CommandOptionType::Channel, "channel", "Channel")
                        .required(true),
                ),
        )
}

pub async fn handle_config_command(
    handler: &Handler,
    ctx: &Context,
    command: &CommandInteraction,
) -> Result<()> {
    let cfg = handler.config.snapshot().await;

    let text = if !is_authorized(&cfg, command) {
        "You need to be a server **Administrator** (or have a role listed in `mod_role_ids`) to change this bot's settings."
            .to_string()
    } else {
        match run(handler, &cfg, ctx, command).await {
            Ok(text) => text,
            Err(e) => {
                tracing::warn!("/config command failed: {e:#}");
                format!("Something went wrong: {e}")
            }
        }
    };

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

fn is_authorized(cfg: &Config, command: &CommandInteraction) -> bool {
    let Some(member) = command.member.as_ref() else {
        return false;
    };
    if !cfg.bot.mod_role_ids.is_empty() {
        return member.roles.iter().any(|r| cfg.bot.mod_role_ids.contains(&r.get()));
    }
    // Discord's own default_member_permissions on the command already restricts
    // who can even see/use it, but a server admin can loosen that in Integration
    // Settings — so this is a defense-in-depth check, not the only gate.
    member.permissions.map(|p| p.administrator()).unwrap_or(false)
}

async fn run(handler: &Handler, cfg: &Config, ctx: &Context, command: &CommandInteraction) -> Result<String> {
    let Some(guild_id) = command.guild_id else {
        return Ok("This command only works in a server.".to_string());
    };

    let options = command.data.options();
    let Some(top) = options.first() else {
        return Ok("Missing subcommand.".to_string());
    };

    Ok(match (top.name, &top.value) {
        ("log-channel", ResolvedValue::SubCommand(sub)) => {
            let Some(channel_id) = find_string(sub).and_then(|s| s.parse::<u64>().ok()) else {
                return Ok("Missing or invalid channel option.".to_string());
            };

            match check_bot_can_post(ctx, guild_id, ChannelId::new(channel_id)).await {
                Ok(None) => {
                    handler.config.set_log_channel(channel_id).await?;
                    format!("Log channel set to <#{channel_id}>.")
                }
                Ok(Some(problem)) => format!(
                    "I can't use <#{channel_id}> as the log channel: {problem} \
                     Fix my permissions there (or pick another channel) and try again."
                ),
                Err(e) => format!("Couldn't check my permissions in <#{channel_id}>: {e}"),
            }
        }

        ("action", ResolvedValue::SubCommand(sub)) => match find_string(sub).and_then(Action::from_toml_str) {
            Some(action) => {
                handler.config.set_action(action).await?;
                let mut reply = format!("Action set to `{}`.", action.as_toml_str());
                if let Some(missing) = missing_permission_for(action) {
                    if let Ok(false) = bot_has_guild_permission(ctx, guild_id, missing).await {
                        reply.push_str(&format!(
                            "\n⚠️ I don't currently have the **{}** permission on this server, \
                             so this action will fail until you grant it to my role.",
                            permission_name(missing)
                        ));
                    }
                }
                reply
            }
            None => "Invalid action value.".to_string(),
        },

        ("timeout-minutes", ResolvedValue::SubCommand(sub)) => match find_integer(sub) {
            Some(minutes) if minutes > 0 => {
                handler.config.set_timeout_minutes(minutes as u64).await?;
                format!("Timeout duration set to {minutes} minute(s).")
            }
            _ => "Invalid duration.".to_string(),
        },

        ("show", _) => build_show_text(cfg),

        ("mod-role", ResolvedValue::SubCommandGroup(group)) => match find_role_action(group) {
            Some(("add", role_id)) => {
                let added = handler.config.add_mod_role(role_id).await?;
                role_reply(role_id, added, "is now allowed to manage this bot", "already had access")
            }
            Some(("remove", role_id)) => {
                let removed = handler.config.remove_mod_role(role_id).await?;
                role_reply(role_id, removed, "can no longer manage this bot", "didn't have access")
            }
            _ => "Missing role option.".to_string(),
        },

        ("exempt-role", ResolvedValue::SubCommandGroup(group)) => match find_role_action(group) {
            Some(("add", role_id)) => {
                let added = handler.config.add_exempt_role(role_id).await?;
                role_reply(role_id, added, "is now exempt from detection", "was already exempt")
            }
            Some(("remove", role_id)) => {
                let removed = handler.config.remove_exempt_role(role_id).await?;
                role_reply(role_id, removed, "is no longer exempt", "wasn't exempt")
            }
            _ => "Missing role option.".to_string(),
        },

        ("exempt-channel", ResolvedValue::SubCommandGroup(group)) => match find_channel_action(group) {
            Some(("add", channel_id)) => {
                let added = handler.config.add_exempt_channel(channel_id).await?;
                channel_reply(channel_id, added, "is now exempt from detection", "was already exempt")
            }
            Some(("remove", channel_id)) => {
                let removed = handler.config.remove_exempt_channel(channel_id).await?;
                channel_reply(channel_id, removed, "is no longer exempt", "wasn't exempt")
            }
            _ => "Missing channel option.".to_string(),
        },

        _ => "Unknown subcommand.".to_string(),
    })
}

/// Responds to autocomplete requests for the `log-channel channel` option: only
/// text channels the bot can actually send messages in, matching what's typed.
pub async fn handle_config_autocomplete(ctx: &Context, command: &CommandInteraction) -> Result<()> {
    let options = command.data.options();
    let typed = options
        .first()
        .and_then(|top| match &top.value {
            ResolvedValue::SubCommand(sub) if top.name == "log-channel" => {
                sub.iter().find_map(|o| match o.value {
                    ResolvedValue::Autocomplete { value, .. } => Some(value),
                    _ => None,
                })
            }
            _ => None,
        })
        .unwrap_or("");

    let choices = match command.guild_id {
        Some(guild_id) => postable_channels(ctx, guild_id, typed).await,
        None => Vec::new(),
    };

    let mut response = CreateAutocompleteResponse::new();
    for (name, id) in choices {
        response = response.add_string_choice(name, id);
    }

    command
        .create_response(&ctx.http, CreateInteractionResponse::Autocomplete(response))
        .await?;
    Ok(())
}

async fn postable_channels(ctx: &Context, guild_id: GuildId, typed: &str) -> Vec<(String, String)> {
    let Some(guild) = ctx.cache.guild(guild_id).map(|g| g.clone()) else {
        return Vec::new();
    };
    let bot_id = ctx.cache.current_user().id;
    let Ok(bot_member) = guild_id.member(&ctx.http, bot_id).await else {
        return Vec::new();
    };

    let typed_lower = typed.to_lowercase();
    let mut matches: Vec<(String, String)> = guild
        .channels
        .values()
        .filter(|c| matches!(c.kind, ChannelType::Text | ChannelType::News))
        .filter(|c| guild.user_permissions_in(c, &bot_member).send_messages())
        .filter(|c| typed.is_empty() || c.name.to_lowercase().contains(&typed_lower))
        .map(|c| (format!("#{}", c.name), c.id.get().to_string()))
        .collect();
    matches.sort_by(|a, b| a.0.cmp(&b.0));
    matches.truncate(25); // Discord's own limit on autocomplete choices.
    matches
}

/// Checks whether the bot can actually do its job (send messages, embed the
/// evidence, attach the flagged image) in a candidate log channel. Returns
/// `Ok(None)` if all good, `Ok(Some(explanation))` if something's missing.
async fn check_bot_can_post(ctx: &Context, guild_id: GuildId, channel_id: ChannelId) -> Result<Option<String>> {
    let Some(guild) = ctx.cache.guild(guild_id).map(|g| g.clone()) else {
        return Ok(Some("I couldn't find this server in my cache.".to_string()));
    };
    let Some(channel) = guild.channels.get(&channel_id).cloned() else {
        return Ok(Some("that channel doesn't exist (or isn't a text channel) in this server.".to_string()));
    };
    let bot_id = ctx.cache.current_user().id;
    let bot_member = guild_id.member(&ctx.http, bot_id).await?;
    let perms = guild.user_permissions_in(&channel, &bot_member);

    let mut missing = Vec::new();
    if !perms.view_channel() {
        missing.push("View Channel");
    }
    if !perms.send_messages() {
        missing.push("Send Messages");
    }
    if !perms.embed_links() {
        missing.push("Embed Links");
    }
    if !perms.attach_files() {
        missing.push("Attach Files");
    }

    if missing.is_empty() {
        Ok(None)
    } else {
        Ok(Some(format!("I'm missing: **{}**.", missing.join(", "))))
    }
}

fn missing_permission_for(action: Action) -> Option<Permissions> {
    match action {
        Action::DeleteTimeout => Some(Permissions::MODERATE_MEMBERS),
        Action::DeleteKick => Some(Permissions::KICK_MEMBERS),
        Action::DeleteBan => Some(Permissions::BAN_MEMBERS),
        Action::LogOnly | Action::DeleteOnly => None,
    }
}

fn permission_name(perm: Permissions) -> &'static str {
    if perm.contains(Permissions::MODERATE_MEMBERS) {
        "Moderate Members"
    } else if perm.contains(Permissions::KICK_MEMBERS) {
        "Kick Members"
    } else if perm.contains(Permissions::BAN_MEMBERS) {
        "Ban Members"
    } else {
        "required"
    }
}

/// Guild-wide permission check (timeout/kick/ban aren't channel-scoped, so
/// channel overwrites don't apply — a plain role-based check is correct here).
#[allow(deprecated)]
async fn bot_has_guild_permission(ctx: &Context, guild_id: GuildId, perm: Permissions) -> Result<bool> {
    let bot_id = ctx.cache.current_user().id;
    let bot_member = guild_id.member(&ctx.http, bot_id).await?;
    Ok(bot_member.permissions(&ctx.cache)?.contains(perm))
}

fn find_string<'a>(sub: &[ResolvedOption<'a>]) -> Option<&'a str> {
    sub.iter().find_map(|o| match o.value {
        ResolvedValue::String(s) => Some(s),
        ResolvedValue::Autocomplete { value, .. } => Some(value),
        _ => None,
    })
}

fn find_integer(sub: &[ResolvedOption]) -> Option<i64> {
    sub.iter().find_map(|o| match o.value {
        ResolvedValue::Integer(i) => Some(i),
        _ => None,
    })
}

/// A subcommand group always resolves to exactly one chosen subcommand (`add` or
/// `remove` here) carrying its own options.
fn find_role_action<'a>(group: &'a [ResolvedOption<'a>]) -> Option<(&'a str, u64)> {
    let chosen = group.first()?;
    let ResolvedValue::SubCommand(sub) = &chosen.value else {
        return None;
    };
    let role_id = find_role(sub)?;
    Some((chosen.name, role_id))
}

fn find_channel_action<'a>(group: &'a [ResolvedOption<'a>]) -> Option<(&'a str, u64)> {
    let chosen = group.first()?;
    let ResolvedValue::SubCommand(sub) = &chosen.value else {
        return None;
    };
    let channel_id = find_channel(sub)?;
    Some((chosen.name, channel_id))
}

fn find_channel(sub: &[ResolvedOption]) -> Option<u64> {
    sub.iter().find_map(|o| match o.value {
        ResolvedValue::Channel(c) => Some(c.id.get()),
        _ => None,
    })
}

fn find_role(sub: &[ResolvedOption]) -> Option<u64> {
    sub.iter().find_map(|o| match o.value {
        ResolvedValue::Role(r) => Some(r.id.get()),
        _ => None,
    })
}

fn role_reply(role_id: u64, changed: bool, did: &str, already: &str) -> String {
    if changed {
        format!("<@&{role_id}> {did}.")
    } else {
        format!("<@&{role_id}> {already}.")
    }
}

fn channel_reply(channel_id: u64, changed: bool, did: &str, already: &str) -> String {
    if changed {
        format!("<#{channel_id}> {did}.")
    } else {
        format!("<#{channel_id}> {already}.")
    }
}

fn build_show_text(cfg: &Config) -> String {
    let log_channel = if cfg.bot.log_channel_id == 0 {
        "disabled".to_string()
    } else {
        format!("<#{}>", cfg.bot.log_channel_id)
    };

    let mod_roles = format_role_list(&cfg.bot.mod_role_ids);
    let exempt_roles = format_role_list(&cfg.moderation.exempt_role_ids);
    let exempt_channels = format_channel_list(&cfg.moderation.exempt_channel_ids);

    format!(
        "**Current settings**\n\
         - Action: `{}`\n\
         - Timeout duration: {} minute(s)\n\
         - Log channel: {log_channel}\n\
         - Mod roles: {mod_roles}\n\
         - Exempt roles: {exempt_roles}\n\
         - Exempt channels: {exempt_channels}\n\
         - Match threshold: {} (hash distance)\n\
         - Flood detection: {} (min {} channels within {}s)\n\
         - Link images: {} ({} allow-listed host(s))",
        cfg.moderation.action.as_toml_str(),
        cfg.moderation.timeout_minutes,
        cfg.detection.match_threshold,
        if cfg.flood.enabled { "on" } else { "off" },
        cfg.flood.min_channels,
        cfg.flood.window_seconds,
        if cfg.links.enabled { "on" } else { "off" },
        cfg.links.allowed_hosts.len(),
    )
}

fn format_role_list(ids: &[u64]) -> String {
    if ids.is_empty() {
        "none (falls back to the Administrator permission)".to_string()
    } else {
        ids.iter().map(|id| format!("<@&{id}>")).collect::<Vec<_>>().join(", ")
    }
}

fn format_channel_list(ids: &[u64]) -> String {
    if ids.is_empty() {
        "none".to_string()
    } else {
        ids.iter().map(|id| format!("<#{id}>")).collect::<Vec<_>>().join(", ")
    }
}
