use std::path::Path;

use anyhow::{Context, Result};
use serde::Deserialize;

#[derive(Debug, Deserialize, Clone)]
pub struct Config {
    pub bot: BotConfig,
    pub moderation: ModerationConfig,
    pub detection: DetectionConfig,
    pub flood: FloodConfig,
}

#[derive(Debug, Deserialize, Clone)]
pub struct BotConfig {
    pub prefix: String,
    pub log_channel_id: u64,
    #[serde(default)]
    pub mod_role_ids: Vec<u64>,
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

#[derive(Debug, Deserialize, Clone)]
pub struct ModerationConfig {
    pub action: Action,
    pub timeout_minutes: u64,
    #[serde(default)]
    pub exempt_role_ids: Vec<u64>,
    #[serde(default)]
    pub exempt_channel_ids: Vec<u64>,
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
