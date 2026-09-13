# discord-anti-scam-bot

A Discord bot (Rust / serenity) that scans every image posted on a server at scale to detect
screenshots from compromised accounts (Nitro/crypto scams mass-reposted), automatically deletes
the offending messages, and sanctions the account according to config.

## How it works

1. On startup, the bot loads every image in the `reference/` folder (screenshots of already
   identified compromised accounts) and computes their perceptual hash.
2. Every image sent on the server — as an attachment, or as a plain link to an allow-listed image
   host such as imgur — is downloaded, hashed, and compared against that reference set (Hamming
   distance). A match below `match_threshold` triggers a detection — even if the image has been
   recompressed/cropped, including a crop down to just the middle of the screenshot.
3. In addition: if the same account posts the same image across several different channels in a
   short time (typical of a compromised account spamming everywhere it has access to), it's
   flagged even if the image isn't in the reference set yet. This activity is persisted to
   SQLite, so it survives a bot restart.
4. Based on `config.toml`, the bot deletes the message and applies (or not) a sanction: timeout,
   kick, or ban. Every detection is logged to a dedicated channel with evidence (image, matched
   reference, score, action taken).

## Invite the bot

[Add discord-anti-scam-bot to your server](https://discord.com/oauth2/authorize?client_id=1548610246358995014&permissions=1101659235334&integration_type=0&scope=bot)

## Discord setup (Developer Portal)

The bot needs the privileged **Message Content** intent enabled under the "Bot" tab of your
application (https://discord.com/developers/applications) — without it, the bot can't see the
text or attachments of messages it didn't send itself.

Required permissions for the bot's role on the server (placed above regular member roles):
- `Manage Messages` (delete scam messages)
- `Moderate Members` (timeout)
- `Kick Members` / `Ban Members` if you use `delete_kick` / `delete_ban`
- `View Channels` / `Read Message History` on the channels to monitor
- `View Channels`, `Send Messages`, `Embed Links`, `Attach Files` on the log channel (checked
  live by `/config log-channel`, which only ever suggests channels that already have these)

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
Flood-detection state is kept in a SQLite database at `storage.database_path` (default
`data/bot.sqlite3`), created automatically on first run.

## Run

```bash
cargo run --release
```

## Run with Docker

```bash
cp .env.example .env        # set your DISCORD_TOKEN
cp config.example.toml config.toml   # edit as needed

mkdir -p reference data     # persisted outside the container
# put your reference screenshots in ./reference/

docker compose up -d --build
```

`config.toml`, `reference/`, and `data/` (the SQLite database) are bind-mounted so they persist
across image rebuilds and container recreations — see [docker-compose.yml](docker-compose.yml).
To update after pulling new code: `docker compose up -d --build`.

## Releases

Pushing a version tag (`git tag v0.1.0 && git push origin v0.1.0`) triggers
[.github/workflows/release.yml](.github/workflows/release.yml), which:

- builds a Linux x86_64 binary and attaches it to a new GitHub Release (with auto-generated
  release notes),
- builds and pushes a multi-purpose Docker image to the GitHub Container Registry as
  `ghcr.io/linventif/discord-anti-scam-bot:<version>` and `:latest`.

To run the published image directly instead of building locally, point `docker-compose.yml`'s
`build: .` to `image: ghcr.io/linventif/discord-anti-scam-bot:latest` (or a specific version tag),
then `docker compose up -d` — no local build step or Rust toolchain needed.

Every push to `main` also runs [.github/workflows/ci.yml](.github/workflows/ci.yml) (build + test)
so regressions get caught before they reach a release.

## Moderation commands (in Discord)

Restricted to members with a role listed in `mod_role_ids` (config.toml), or by default to
anyone with the `Manage Messages` permission.

- `!scam add` — attach one or more images to the message: adds them as new scam references
  (useful whenever a moderator spots a new screenshot that isn't known yet).
- `!scam list` — lists the reference files currently in memory.
- `!scam remove <file>` — removes a reference (filename as shown by `list`).

## `/config` slash command

Registered as a **global** command (not per-guild), so it works in every server the bot is
invited to without any extra step — including after being removed and re-added to a server.
Global command registration/updates can take up to about an hour to fully propagate to every
client, so don't be surprised if it's not instant right after a first deploy.

Change settings live from Discord — no editing `config.toml` or restarting by hand. Requires
being a server **Administrator** (or having a role listed in `mod_role_ids`); Discord's UI also
hides the command entirely from members without that permission. All replies are ephemeral
(visible only to whoever ran the command). Role options use Discord's native picker, and `action`
uses a fixed choice list, so there's nothing to type or get wrong.

- `/config log-channel <channel>` — the channel option is autocomplete-driven and only ever
  suggests channels the bot can actually post in (View Channel + Send Messages). If you still
  manage to target one it can't fully use (missing Embed Links / Attach Files), it tells you
  exactly what's missing instead of silently failing later.
- `/config action <value>` — if the chosen action needs a permission the bot doesn't have on this
  server (Moderate Members / Kick Members / Ban Members), the reply warns you immediately instead
  of only failing at detection time.
- `/config timeout-minutes <minutes>`
- `/config mod-role add|remove @role`
- `/config exempt-role add|remove @role`
- `/config exempt-channel add|remove #channel`
- `/config show` — prints the current settings

Every change is written to `config.toml` immediately (only the touched key — comments and the
rest of the file are left alone), so it survives a restart or redeploy, and takes effect right
away without one.

## Key settings (`config.toml`)

- `moderation.action`: `log_only` / `delete_only` / `delete_timeout` (default) /
  `delete_kick` / `delete_ban`.
- `moderation.timeout_minutes`: timeout duration (max 40320 = 28 days, Discord's limit).
- `detection.match_threshold`: image comparison sensitivity (lower = stricter).
- `flood.*`: cross-channel flood detection settings.
- `bot.log_channel_id`: channel where detection evidence gets posted (0 = disabled).
- `bot.exempt_role_ids` / `moderation.exempt_channel_ids`: roles/channels to ignore.
- `links.enabled` / `links.allowed_hosts`: fetch and check images posted as plain links (not
  just attachments) from these hosts only. The bot never fetches an arbitrary URL found in a
  message — only hosts on this list — to avoid becoming an open URL-fetching proxy.
- `storage.database_path`: where the SQLite flood-detection database lives.

## Known limitations (v1)

- Link-based detection only follows one hop past an allow-listed host's own HTML page (e.g. an
  imgur gallery page's `og:image`) — it won't chase further redirects to a different host.

## Contributing

Bug reports, false positive/negative reports, and PRs are welcome — see
[CONTRIBUTING.md](CONTRIBUTING.md) for the dev setup and workflow, and
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) / [docs/DETECTION.md](docs/DETECTION.md) for how the
codebase and the detection pipeline are put together.

## License

[MIT](LICENSE)
