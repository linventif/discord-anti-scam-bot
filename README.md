# discord-anti-scam-bot

A Discord bot (Rust / serenity) that scans every image posted on a server at scale to detect
screenshots from compromised accounts (Nitro/crypto scams mass-reposted), automatically deletes
the offending messages, and sanctions the account according to config.

## How it works

1. On startup, the bot loads every image in the `reference/` folder (screenshots of already
   identified compromised accounts) and computes their perceptual hash.
2. Every image sent on the server is downloaded, hashed, and compared against that reference set
   (Hamming distance). A match below `match_threshold` triggers a detection — even if the image
   has been recompressed/cropped.
3. In addition: if the same account posts the same image across several different channels in a
   short time (typical of a compromised account spamming everywhere it has access to), it's
   flagged even if the image isn't in the reference set yet.
4. Based on `config.toml`, the bot deletes the message and applies (or not) a sanction: timeout,
   kick, or ban. Every detection is logged to a dedicated channel with evidence (image, matched
   reference, score, action taken).

## Invite the bot

[Add discord-anti-scam-bot to your server](https://discord.com/oauth2/authorize?client_id=1548610246358995014&permissions=1101659186182&integration_type=0&scope=bot)

## Discord setup (Developer Portal)

The bot needs the privileged **Message Content** intent enabled under the "Bot" tab of your
application (https://discord.com/developers/applications) — without it, the bot can't see the
text or attachments of messages it didn't send itself.

Required permissions for the bot's role on the server (placed above regular member roles):
- `Manage Messages` (delete scam messages)
- `Moderate Members` (timeout)
- `Kick Members` / `Ban Members` if you use `delete_kick` / `delete_ban`
- `View Channels` / `Read Message History` on the channels to monitor

## Install

```bash
cp .env.example .env
# edit .env and set your DISCORD_TOKEN

cp config.example.toml config.toml
# edit config.toml: at least set bot.log_channel_id, and moderation.action once you're
# done testing (config.toml is gitignored, so your own settings never get committed)

cargo build --release
```

The binary reads `config.toml` at the project root (every option is commented there) and the
`reference/` folder (pre-filled with the initial screenshots gathered when setting up the bot).

## Run

```bash
cargo run --release
```

## Moderation commands (in Discord)

Restricted to members with a role listed in `mod_role_ids` (config.toml), or by default to
anyone with the `Manage Messages` permission.

- `!scam add` — attach one or more images to the message: adds them as new scam references
  (useful whenever a moderator spots a new screenshot that isn't known yet).
- `!scam list` — lists the reference files currently in memory.
- `!scam remove <file>` — removes a reference (filename as shown by `list`).

## Key settings (`config.toml`)

- `moderation.action`: `log_only` / `delete_only` / `delete_timeout` (default) /
  `delete_kick` / `delete_ban`.
- `moderation.timeout_minutes`: timeout duration (max 40320 = 28 days, Discord's limit).
- `detection.match_threshold`: image comparison sensitivity (lower = stricter).
- `flood.*`: cross-channel flood detection settings.
- `bot.log_channel_id`: channel where detection evidence gets posted (0 = disabled).
- `bot.exempt_role_ids` / `moderation.exempt_channel_ids`: roles/channels to ignore.

## Known limitations (v1)

- Only images sent as **attachments** are analyzed, not images embedded via an external link
  (imgur, etc.).
- Flood detection is in-memory: it resets every time the bot restarts.
