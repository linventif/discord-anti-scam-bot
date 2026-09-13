use std::path::Path;

use anyhow::{Context, Result};
use rusqlite::Connection;
use tokio::sync::Mutex;

use crate::config::{Action, GuildConfig};

/// Per-guild moderation settings (log channel, action, mod/exempt roles and
/// channels), persisted in SQLite and keyed by `guild_id`. Kept separate from
/// the flood-detection database's connection (even though they can share the
/// same file) so each store's locking is independent and neither blocks on the
/// other's queries.
pub struct GuildSettingsStore {
    conn: Mutex<Connection>,
}

impl GuildSettingsStore {
    pub fn open(db_path: impl AsRef<Path>) -> Result<Self> {
        let db_path = db_path.as_ref();
        if let Some(parent) = db_path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)
                    .with_context(|| format!("could not create folder {}", parent.display()))?;
            }
        }

        let conn = Connection::open(db_path)
            .with_context(|| format!("could not open database {}", db_path.display()))?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS guild_settings (
                guild_id TEXT PRIMARY KEY,
                log_channel_id TEXT NOT NULL,
                action TEXT NOT NULL,
                timeout_minutes INTEGER NOT NULL,
                mod_role_ids TEXT NOT NULL,
                exempt_role_ids TEXT NOT NULL,
                exempt_channel_ids TEXT NOT NULL
            );",
        )
        .context("could not initialize guild_settings table")?;

        Ok(Self { conn: Mutex::new(conn) })
    }

    pub async fn get(&self, guild_id: u64) -> GuildConfig {
        let conn = self.conn.lock().await;
        read_row(&conn, guild_id)
    }

    pub async fn set_log_channel(&self, guild_id: u64, channel_id: u64) -> Result<()> {
        let conn = self.conn.lock().await;
        let mut cfg = read_row(&conn, guild_id);
        cfg.log_channel_id = channel_id;
        write_row(&conn, guild_id, &cfg)
    }

    pub async fn set_action(&self, guild_id: u64, action: Action) -> Result<()> {
        let conn = self.conn.lock().await;
        let mut cfg = read_row(&conn, guild_id);
        cfg.action = action;
        write_row(&conn, guild_id, &cfg)
    }

    pub async fn set_timeout_minutes(&self, guild_id: u64, minutes: u64) -> Result<()> {
        let conn = self.conn.lock().await;
        let mut cfg = read_row(&conn, guild_id);
        cfg.timeout_minutes = minutes;
        write_row(&conn, guild_id, &cfg)
    }

    pub async fn add_mod_role(&self, guild_id: u64, role_id: u64) -> Result<bool> {
        let conn = self.conn.lock().await;
        let mut cfg = read_row(&conn, guild_id);
        let changed = push_unique(&mut cfg.mod_role_ids, role_id);
        write_row(&conn, guild_id, &cfg)?;
        Ok(changed)
    }

    pub async fn remove_mod_role(&self, guild_id: u64, role_id: u64) -> Result<bool> {
        let conn = self.conn.lock().await;
        let mut cfg = read_row(&conn, guild_id);
        let changed = remove_value(&mut cfg.mod_role_ids, role_id);
        write_row(&conn, guild_id, &cfg)?;
        Ok(changed)
    }

    pub async fn add_exempt_role(&self, guild_id: u64, role_id: u64) -> Result<bool> {
        let conn = self.conn.lock().await;
        let mut cfg = read_row(&conn, guild_id);
        let changed = push_unique(&mut cfg.exempt_role_ids, role_id);
        write_row(&conn, guild_id, &cfg)?;
        Ok(changed)
    }

    pub async fn remove_exempt_role(&self, guild_id: u64, role_id: u64) -> Result<bool> {
        let conn = self.conn.lock().await;
        let mut cfg = read_row(&conn, guild_id);
        let changed = remove_value(&mut cfg.exempt_role_ids, role_id);
        write_row(&conn, guild_id, &cfg)?;
        Ok(changed)
    }

    pub async fn add_exempt_channel(&self, guild_id: u64, channel_id: u64) -> Result<bool> {
        let conn = self.conn.lock().await;
        let mut cfg = read_row(&conn, guild_id);
        let changed = push_unique(&mut cfg.exempt_channel_ids, channel_id);
        write_row(&conn, guild_id, &cfg)?;
        Ok(changed)
    }

    pub async fn remove_exempt_channel(&self, guild_id: u64, channel_id: u64) -> Result<bool> {
        let conn = self.conn.lock().await;
        let mut cfg = read_row(&conn, guild_id);
        let changed = remove_value(&mut cfg.exempt_channel_ids, channel_id);
        write_row(&conn, guild_id, &cfg)?;
        Ok(changed)
    }
}

fn read_row(conn: &Connection, guild_id: u64) -> GuildConfig {
    let result = conn.query_row(
        "SELECT log_channel_id, action, timeout_minutes, mod_role_ids, exempt_role_ids, exempt_channel_ids
         FROM guild_settings WHERE guild_id = ?1",
        [guild_id.to_string()],
        |row| {
            let log_channel_id: String = row.get(0)?;
            let action: String = row.get(1)?;
            let timeout_minutes: i64 = row.get(2)?;
            let mod_role_ids: String = row.get(3)?;
            let exempt_role_ids: String = row.get(4)?;
            let exempt_channel_ids: String = row.get(5)?;
            Ok((log_channel_id, action, timeout_minutes, mod_role_ids, exempt_role_ids, exempt_channel_ids))
        },
    );

    match result {
        Ok((log_channel_id, action, timeout_minutes, mod_role_ids, exempt_role_ids, exempt_channel_ids)) => {
            let default = GuildConfig::default();
            GuildConfig {
                log_channel_id: log_channel_id.parse().unwrap_or(default.log_channel_id),
                action: Action::from_toml_str(&action).unwrap_or(default.action),
                timeout_minutes: u64::try_from(timeout_minutes).unwrap_or(default.timeout_minutes),
                mod_role_ids: parse_ids(&mod_role_ids),
                exempt_role_ids: parse_ids(&exempt_role_ids),
                exempt_channel_ids: parse_ids(&exempt_channel_ids),
            }
        }
        Err(rusqlite::Error::QueryReturnedNoRows) => GuildConfig::default(),
        Err(e) => {
            tracing::warn!("could not read guild_settings for {guild_id}: {e}, using defaults");
            GuildConfig::default()
        }
    }
}

fn write_row(conn: &Connection, guild_id: u64, cfg: &GuildConfig) -> Result<()> {
    conn.execute(
        "INSERT INTO guild_settings
            (guild_id, log_channel_id, action, timeout_minutes, mod_role_ids, exempt_role_ids, exempt_channel_ids)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
         ON CONFLICT(guild_id) DO UPDATE SET
            log_channel_id = excluded.log_channel_id,
            action = excluded.action,
            timeout_minutes = excluded.timeout_minutes,
            mod_role_ids = excluded.mod_role_ids,
            exempt_role_ids = excluded.exempt_role_ids,
            exempt_channel_ids = excluded.exempt_channel_ids",
        rusqlite::params![
            guild_id.to_string(),
            cfg.log_channel_id.to_string(),
            cfg.action.as_toml_str(),
            cfg.timeout_minutes as i64,
            format_ids(&cfg.mod_role_ids),
            format_ids(&cfg.exempt_role_ids),
            format_ids(&cfg.exempt_channel_ids),
        ],
    )
    .with_context(|| format!("could not write guild_settings for {guild_id}"))?;
    Ok(())
}

fn format_ids(ids: &[u64]) -> String {
    ids.iter().map(u64::to_string).collect::<Vec<_>>().join(",")
}

fn parse_ids(s: &str) -> Vec<u64> {
    s.split(',').filter(|p| !p.is_empty()).filter_map(|p| p.parse().ok()).collect()
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

    #[tokio::test]
    async fn settings_are_isolated_per_guild() {
        let store = GuildSettingsStore::open(":memory:").expect("open in-memory db");

        store.set_log_channel(1, 111).await.unwrap();
        store.set_log_channel(2, 222).await.unwrap();
        store.set_action(1, Action::DeleteBan).await.unwrap();

        let guild1 = store.get(1).await;
        let guild2 = store.get(2).await;

        assert_eq!(guild1.log_channel_id, 111);
        assert_eq!(guild1.action, Action::DeleteBan);
        assert_eq!(guild2.log_channel_id, 222);
        assert_eq!(guild2.action, Action::DeleteTimeout, "guild 2 must keep the default, unaffected by guild 1's change");
    }

    #[tokio::test]
    async fn unconfigured_guild_gets_defaults() {
        let store = GuildSettingsStore::open(":memory:").expect("open in-memory db");
        let cfg = store.get(999).await;
        assert_eq!(cfg, GuildConfig::default());
    }

    #[tokio::test]
    async fn role_and_channel_lists_add_and_remove() {
        let store = GuildSettingsStore::open(":memory:").expect("open in-memory db");
        let guild_id = 1;

        assert!(store.add_mod_role(guild_id, 10).await.unwrap());
        assert!(!store.add_mod_role(guild_id, 10).await.unwrap(), "adding twice is a no-op");
        assert!(store.add_exempt_role(guild_id, 20).await.unwrap());
        assert!(store.add_exempt_channel(guild_id, 30).await.unwrap());

        let cfg = store.get(guild_id).await;
        assert_eq!(cfg.mod_role_ids, vec![10]);
        assert_eq!(cfg.exempt_role_ids, vec![20]);
        assert_eq!(cfg.exempt_channel_ids, vec![30]);

        assert!(store.remove_mod_role(guild_id, 10).await.unwrap());
        assert!(!store.remove_mod_role(guild_id, 10).await.unwrap(), "already removed");
        assert!(store.get(guild_id).await.mod_role_ids.is_empty());
    }
}
