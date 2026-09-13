use std::path::PathBuf;

use anyhow::{Context, Result};
use tokio::sync::RwLock;
use toml_edit::DocumentMut;

use crate::config::{Action, Config};

/// Holds the live config plus the on-disk path it came from. `/config` slash
/// commands mutate both: the in-memory copy (so the change applies immediately)
/// and the file on disk via `toml_edit` (so it survives a restart) — surgically,
/// touching only the changed key, so comments and formatting elsewhere in
/// config.toml are left alone.
pub struct ConfigStore {
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

    async fn edit_file(&self, f: impl FnOnce(&mut DocumentMut)) -> Result<()> {
        let raw = tokio::fs::read_to_string(&self.path)
            .await
            .with_context(|| format!("reading {}", self.path.display()))?;
        let mut doc = raw
            .parse::<DocumentMut>()
            .with_context(|| format!("parsing {}", self.path.display()))?;
        f(&mut doc);
        tokio::fs::write(&self.path, doc.to_string())
            .await
            .with_context(|| format!("writing {}", self.path.display()))?;
        Ok(())
    }

    pub async fn set_log_channel(&self, channel_id: u64) -> Result<()> {
        self.edit_file(|doc| {
            doc["bot"]["log_channel_id"] = toml_edit::value(channel_id as i64);
        })
        .await?;
        self.inner.write().await.bot.log_channel_id = channel_id;
        Ok(())
    }

    pub async fn set_action(&self, action: Action) -> Result<()> {
        self.edit_file(|doc| {
            doc["moderation"]["action"] = toml_edit::value(action.as_toml_str());
        })
        .await?;
        self.inner.write().await.moderation.action = action;
        Ok(())
    }

    pub async fn set_timeout_minutes(&self, minutes: u64) -> Result<()> {
        self.edit_file(|doc| {
            doc["moderation"]["timeout_minutes"] = toml_edit::value(minutes as i64);
        })
        .await?;
        self.inner.write().await.moderation.timeout_minutes = minutes;
        Ok(())
    }

    pub async fn add_mod_role(&self, role_id: u64) -> Result<bool> {
        self.add_to_array("bot", "mod_role_ids", role_id).await?;
        let mut cfg = self.inner.write().await;
        Ok(push_unique(&mut cfg.bot.mod_role_ids, role_id))
    }

    pub async fn remove_mod_role(&self, role_id: u64) -> Result<bool> {
        self.remove_from_array("bot", "mod_role_ids", role_id).await?;
        let mut cfg = self.inner.write().await;
        Ok(remove_value(&mut cfg.bot.mod_role_ids, role_id))
    }

    pub async fn add_exempt_role(&self, role_id: u64) -> Result<bool> {
        self.add_to_array("moderation", "exempt_role_ids", role_id).await?;
        let mut cfg = self.inner.write().await;
        Ok(push_unique(&mut cfg.moderation.exempt_role_ids, role_id))
    }

    pub async fn remove_exempt_role(&self, role_id: u64) -> Result<bool> {
        self.remove_from_array("moderation", "exempt_role_ids", role_id).await?;
        let mut cfg = self.inner.write().await;
        Ok(remove_value(&mut cfg.moderation.exempt_role_ids, role_id))
    }

    pub async fn add_exempt_channel(&self, channel_id: u64) -> Result<bool> {
        self.add_to_array("moderation", "exempt_channel_ids", channel_id).await?;
        let mut cfg = self.inner.write().await;
        Ok(push_unique(&mut cfg.moderation.exempt_channel_ids, channel_id))
    }

    pub async fn remove_exempt_channel(&self, channel_id: u64) -> Result<bool> {
        self.remove_from_array("moderation", "exempt_channel_ids", channel_id).await?;
        let mut cfg = self.inner.write().await;
        Ok(remove_value(&mut cfg.moderation.exempt_channel_ids, channel_id))
    }

    async fn add_to_array(&self, table: &str, key: &str, value: u64) -> Result<()> {
        let table = table.to_string();
        let key = key.to_string();
        self.edit_file(move |doc| {
            let item = doc[&table][&key].or_insert(toml_edit::array());
            if let Some(arr) = item.as_array_mut() {
                let already_present = arr.iter().any(|v| v.as_integer() == Some(value as i64));
                if !already_present {
                    arr.push(value as i64);
                }
            }
        })
        .await
    }

    async fn remove_from_array(&self, table: &str, key: &str, value: u64) -> Result<()> {
        let table = table.to_string();
        let key = key.to_string();
        self.edit_file(move |doc| {
            if let Some(arr) = doc[&table][&key].as_array_mut() {
                let idx = arr.iter().position(|v| v.as_integer() == Some(value as i64));
                if let Some(idx) = idx {
                    arr.remove(idx);
                }
            }
        })
        .await
    }
}

fn push_unique(vec: &mut Vec<u64>, value: u64) -> bool {
    if vec.contains(&value) {
        false
    } else {
        vec.push(value);
        true
    }
}

fn remove_value(vec: &mut Vec<u64>, value: u64) -> bool {
    let before = vec.len();
    vec.retain(|v| *v != value);
    vec.len() != before
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn temp_store() -> (ConfigStore, std::path::PathBuf) {
        let path = std::env::temp_dir().join(format!(
            "discord_anti_scam_bot_config_test_{}_{}.toml",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::copy("config.example.toml", &path).expect("copy config.example.toml");
        let store = ConfigStore::load(&path).expect("load config");
        (store, path)
    }

    #[tokio::test]
    async fn edits_survive_a_reload_and_keep_comments() {
        let (store, path) = temp_store().await;

        store.set_log_channel(123456789).await.unwrap();
        store.set_action(Action::DeleteBan).await.unwrap();
        store.set_timeout_minutes(60).await.unwrap();
        assert!(store.add_mod_role(111).await.unwrap());
        assert!(!store.add_mod_role(111).await.unwrap(), "adding twice is a no-op");
        assert!(store.add_exempt_channel(222).await.unwrap());
        assert!(store.remove_exempt_channel(222).await.unwrap());
        assert!(!store.remove_exempt_channel(222).await.unwrap(), "already removed");

        // In-memory view reflects the changes immediately.
        let snap = store.snapshot().await;
        assert_eq!(snap.bot.log_channel_id, 123456789);
        assert_eq!(snap.moderation.action, Action::DeleteBan);
        assert_eq!(snap.moderation.timeout_minutes, 60);
        assert_eq!(snap.bot.mod_role_ids, vec![111]);
        assert!(snap.moderation.exempt_channel_ids.is_empty());

        // And a fresh load from disk (simulating a restart) matches too.
        let reloaded = Config::load(&path).expect("reload from disk");
        assert_eq!(reloaded.bot.log_channel_id, 123456789);
        assert_eq!(reloaded.moderation.action, Action::DeleteBan);
        assert_eq!(reloaded.bot.mod_role_ids, vec![111]);

        let raw = std::fs::read_to_string(&path).unwrap();
        assert!(
            raw.contains("# The bot token does NOT go here"),
            "surgical edits should leave unrelated comments intact"
        );

        let _ = std::fs::remove_file(&path);
    }
}
