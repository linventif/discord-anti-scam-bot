use anyhow::Result;
use serenity::all::*;

use crate::config::Action;
use crate::handler::Handler;

/// Builds the `/config` command tree: flat subcommands for single-value settings,
/// and a subcommand group (`add`/`remove`) for each of the three role/channel
/// lists. Channel and role options get Discord's native picker UI; `action` gets
/// a fixed choice list — no custom autocomplete plumbing needed for either.
pub fn build_config_command() -> CreateCommand {
    CreateCommand::new("config")
        .description("View or change discord-anti-scam-bot settings for this server")
        .default_member_permissions(Permissions::MANAGE_MESSAGES)
        .add_option(
            CreateCommandOption::new(
                CommandOptionType::SubCommand,
                "log-channel",
                "Channel where detection evidence gets posted",
            )
            .add_sub_option(
                CreateCommandOption::new(CommandOptionType::Channel, "channel", "The log channel")
                    .required(true),
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
    let text = if !is_authorized(command) {
        "You need the **Manage Messages** permission (or a configured mod role) to change this bot's settings."
            .to_string()
    } else {
        match run(handler, command).await {
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

fn is_authorized(command: &CommandInteraction) -> bool {
    // Discord's own default_member_permissions on the command already restricts
    // who can even see/use it, but a server admin can loosen that in Integration
    // Settings — so this is a defense-in-depth check, not the only gate.
    command
        .member
        .as_ref()
        .and_then(|m| m.permissions)
        .map(|p| p.manage_messages())
        .unwrap_or(false)
}

async fn run(handler: &Handler, command: &CommandInteraction) -> Result<String> {
    let options = command.data.options();
    let Some(top) = options.first() else {
        return Ok("Missing subcommand.".to_string());
    };

    Ok(match (top.name, &top.value) {
        ("log-channel", ResolvedValue::SubCommand(sub)) => match find_channel(sub) {
            Some(id) => {
                handler.config.set_log_channel(id).await?;
                format!("Log channel set to <#{id}>.")
            }
            None => "Missing channel option.".to_string(),
        },

        ("action", ResolvedValue::SubCommand(sub)) => match find_string(sub).and_then(Action::from_toml_str) {
            Some(action) => {
                handler.config.set_action(action).await?;
                format!("Action set to `{}`.", action.as_toml_str())
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

        ("show", _) => build_show_text(&handler.config.snapshot().await),

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

fn find_channel(sub: &[ResolvedOption]) -> Option<u64> {
    sub.iter().find_map(|o| match o.value {
        ResolvedValue::Channel(c) => Some(c.id.get()),
        _ => None,
    })
}

fn find_string<'a>(sub: &[ResolvedOption<'a>]) -> Option<&'a str> {
    sub.iter().find_map(|o| match o.value {
        ResolvedValue::String(s) => Some(s),
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

fn build_show_text(cfg: &crate::config::Config) -> String {
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
        "none (falls back to the Manage Messages permission)".to_string()
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
