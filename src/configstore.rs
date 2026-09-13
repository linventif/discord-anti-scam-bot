use std::path::PathBuf;

use anyhow::Result;
use tokio::sync::RwLock;

use crate::config::Config;

/// Holds the bot-wide config loaded from config.toml. Nothing in here is
/// currently editable at runtime (the settings that are — log channel, action,
/// roles... — are per-guild and live in `GuildSettingsStore` instead), but this
/// still goes through a lock rather than a bare `Config` so a future global
/// runtime-editable setting doesn't require another refactor.
pub struct ConfigStore {
    #[allow(dead_code)]
    path: PathBuf,
    inner: RwLock<Config>,
}

impl ConfigStore {
    pub fn load(path: impl Into<PathBuf>) -> Result<Self> {
        let path = path.into();
        let config = Config::load(&path)?;
        Ok(Self {
            path,
            inner: RwLock::new(config),
        })
    }

    pub async fn snapshot(&self) -> Config {
        self.inner.read().await.clone()
    }
}
