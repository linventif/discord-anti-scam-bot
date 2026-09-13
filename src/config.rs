use std::path::Path;

use anyhow::{Context, Result};
use serde::Deserialize;

/// Bot-wide operational settings — the same for every guild the bot is in.
/// Per-guild moderation settings (log channel, action, roles...) live in
/// `GuildConfig` / `GuildSettingsStore` instead, since those legitimately
/// differ from one server to the next.
#[derive(Debug, Deserialize, Clone)]
pub struct Config {
    pub bot: BotConfig,
    pub detection: DetectionConfig,
    pub flood: FloodConfig,
    pub links: LinksConfig,
    pub storage: StorageConfig,
}

#[derive(Debug, Deserialize, Clone)]
pub struct BotConfig {
    pub prefix: String,
}

#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    LogOnly,
    DeleteOnly,
    DeleteTimeout,
    DeleteKick,
    DeleteBan,
}

impl Action {
    /// The exact string this variant is written/read as (config.toml and the
    /// `guild_settings` SQLite table both use this).
    pub fn as_toml_str(self) -> &'static str {
        match self {
            Action::LogOnly => "log_only",
            Action::DeleteOnly => "delete_only",
            Action::DeleteTimeout => "delete_timeout",
            Action::DeleteKick => "delete_kick",
            Action::DeleteBan => "delete_ban",
        }
    }

    pub fn from_toml_str(s: &str) -> Option<Self> {
        match s {
            "log_only" => Some(Action::LogOnly),
            "delete_only" => Some(Action::DeleteOnly),
            "delete_timeout" => Some(Action::DeleteTimeout),
            "delete_kick" => Some(Action::DeleteKick),
            "delete_ban" => Some(Action::DeleteBan),
            _ => None,
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct DetectionConfig {
    pub reference_dir: String,
    pub match_threshold: u32,
}

#[derive(Debug, Deserialize, Clone)]
pub struct FloodConfig {
    pub enabled: bool,
    pub min_channels: usize,
    pub window_seconds: u64,
    pub same_image_threshold: u32,
}

#[derive(Debug, Deserialize, Clone)]
pub struct LinksConfig {
    pub enabled: bool,
    #[serde(default)]
    pub allowed_hosts: Vec<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct StorageConfig {
    pub database_path: String,
}

impl Config {
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("could not read {}", path.display()))?;
        let cfg: Config = toml::from_str(&raw)
            .with_context(|| format!("invalid config in {}", path.display()))?;
        Ok(cfg)
    }
}

/// Per-guild moderation settings, persisted in the `guild_settings` SQLite
/// table (see `guildstore.rs`). Unset fields fall back to these defaults —
/// there's no config.toml equivalent, since "the default for every guild
/// until someone runs /config" is a code-level fact, not deployment config.
#[derive(Debug, Clone, PartialEq)]
pub struct GuildConfig {
    pub log_channel_id: u64,
    pub action: Action,
    pub timeout_minutes: u64,
    pub mod_role_ids: Vec<u64>,
    pub exempt_role_ids: Vec<u64>,
    pub exempt_channel_ids: Vec<u64>,
}

impl Default for GuildConfig {
    fn default() -> Self {
        Self {
            log_channel_id: 0,
            action: Action::DeleteTimeout,
            timeout_minutes: 1440,
            mod_role_ids: Vec::new(),
            exempt_role_ids: Vec::new(),
            exempt_channel_ids: Vec::new(),
        }
    }
}
