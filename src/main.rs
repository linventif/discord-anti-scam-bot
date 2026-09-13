mod commands;
mod config;
mod configstore;
mod flood;
mod handler;
mod hashstore;
mod linkimage;
mod slashconfig;

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context as _, Result};
use serenity::prelude::*;
use tracing_subscriber::EnvFilter;

use configstore::ConfigStore;
use flood::FloodDetector;
use handler::Handler;
use hashstore::ReferenceStore;
use linkimage::LinkImageFetcher;

#[tokio::main]
async fn main() -> Result<()> {
    dotenvy::dotenv().ok();
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .init();

    let config_store = Arc::new(ConfigStore::load("config.toml").context("loading config.toml")?);
    let config = config_store.snapshot().await;

    let store = Arc::new(ReferenceStore::new(&config.detection.reference_dir));
    let loaded = store.load_dir().await.context("loading the reference folder")?;
    tracing::info!(
        "{loaded} reference image(s) loaded from '{}'",
        config.detection.reference_dir
    );

    let flood = Arc::new(
        FloodDetector::open(
            &config.storage.database_path,
            config.flood.window_seconds,
            config.flood.same_image_threshold,
            config.flood.min_channels,
        )
        .context("opening the flood-detection database")?,
    );

    {
        let flood = flood.clone();
        let sweep_interval = Duration::from_secs(config.flood.window_seconds.max(60) * 2);
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(sweep_interval);
            loop {
                ticker.tick().await;
                flood.sweep().await;
            }
        });
    }

    let links = LinkImageFetcher::new(&config.links.allowed_hosts);

    let token = std::env::var("DISCORD_TOKEN")
        .context("missing DISCORD_TOKEN environment variable (see .env.example)")?;

    let intents = GatewayIntents::GUILDS | GatewayIntents::GUILD_MESSAGES | GatewayIntents::MESSAGE_CONTENT;

    let handler = Handler {
        config: config_store,
        store,
        flood,
        links,
    };

    let mut client = Client::builder(&token, intents)
        .event_handler(handler)
        .await
        .context("could not create the Discord client")?;

    client.start().await.context("error while running the Discord client")?;

    Ok(())
}
