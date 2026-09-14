# discord-anti-scam-bot

A Discord bot (Rust / serenity) that scans every image posted on a server at scale to detect
screenshots from compromised accounts (Nitro/crypto scams mass-reposted), automatically deletes
the offending messages, and sanctions the account according to config. Built to run in multiple
servers at once, each with its own independent settings — see [Per-server
settings](#per-server-settings-config-above) below.

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
4. Based on that server's `/config` settings, the bot deletes the message and applies (or not) a
   sanction: timeout, kick, or ban. Every detection is logged to that server's own dedicated
   channel with evidence (image, matched
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
# edit config.toml for bot-wide settings (detection sensitivity, flood tuning, allow-listed
# link hosts...) — config.toml is gitignored, so your own values never get committed.
# Per-server settings (log channel, sanction, mod/exempt roles) are NOT in this file: set
# those with /config once the bot is running and invited to your server(s).

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

docker compose up -d --build
```

`config.toml`, `reference/`, and `data/` (the SQLite database) are bind-mounted so they persist
across image rebuilds and container recreations — see [docker-compose.yml](docker-compose.yml).
To update after pulling new code: `docker compose up -d --build`.

The image ships with the reference screenshots already committed to this repo baked in (see
[Dockerfile](Dockerfile)), so a fresh deploy has them from the start — `!scam add` (or dropping
files into `./reference/` and restarting) still adds more on top, persisted via the bind mount.

If deploying via a PaaS (Dokploy, Coolify, etc.) that pulls a pre-built image (e.g. from
`ghcr.io/linventif/discord-anti-scam-bot`) rather than building from this repo, remember the
container's working directory is `/app` (see the Dockerfile's `WORKDIR`) — mount `config.toml`,
`reference/`, and `data/` at `/app/config.toml`, `/app/reference`, and `/app/data` respectively,
not at `/`.

### Logs

The bot logs to **stdout** (`tracing_subscriber`), not to a file — there's nothing inside the
container to rotate or clean up. `docker compose logs -f bot` (or your platform's log viewer)
shows it live. [docker-compose.yml](docker-compose.yml) caps Docker's own log storage (`json-file`
driver, 10 MiB × 5 files) so it can't grow unbounded on the host; if you deploy via a PaaS that
doesn't go through this compose file (e.g. Dokploy's image-based "Application" mode rather than
its "Compose" mode), it manages log capture and retention itself instead.

Verbosity is controlled by the standard `RUST_LOG` env var (e.g. `RUST_LOG=debug`, or
`RUST_LOG=discord_anti_scam_bot=debug,warn` to go verbose for just this crate) — unset, it
defaults to `info`.

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

Restricted to members with a role listed in this server's `mod_role_ids` (see `/config mod-role`
below), or by default to anyone with the `Manage Messages` permission.

- `!scam add` — attach one or more images to the message: adds them as new scam references
  (useful whenever a moderator spots a new screenshot that isn't known yet).
- `!scam list` — lists the reference files currently in memory.
- `!scam remove <file>` — removes a reference (filename as shown by `list`).

The reference set itself is shared across every server the bot is in (a scam flagged on one
server is recognized on all of them) — only who's *allowed to manage it* is checked per-server.

## `/config` slash command

Registered as a **global** command (not per-guild), so it works in every server the bot is
invited to without any extra step — including after being removed and re-added to a server.
Global command registration/updates can take up to about an hour to fully propagate to every
client, so don't be surprised if it's not instant right after a first deploy.

Every setting `/config` touches is **specific to the server you run it in** — running it in one
server never reads or changes another server's settings (see
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md#multi-guild-bot-wide-vs-per-guild-settings)). Change
settings live from Discord — no editing files or restarting by hand. Requires being a server
**Administrator** (or having a role listed in this server's `mod_role_ids`); Discord's UI also
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
- `/config show` — prints this server's current settings

Every change is written to the database immediately, so it survives a restart or redeploy, and
takes effect right away without one.

## Per-server settings (`/config`, above)

- `action`: `log_only` / `delete_only` / `delete_timeout` (default) / `delete_kick` /
  `delete_ban`.
- `timeout_minutes`: timeout duration (max 40320 = 28 days, Discord's limit).
- `log_channel_id`: channel where detection evidence gets posted (0/unset = disabled).
- `mod_role_ids`: who besides Administrators can use `/config` and `!scam add/list/remove`.
- `exempt_role_ids` / `exempt_channel_ids`: roles/channels to ignore.

## Bot-wide settings (`config.toml`, same for every server)

- `detection.match_threshold`: image comparison sensitivity (lower = stricter).
- `flood.*`: cross-channel flood detection settings.
- `links.enabled` / `links.allowed_hosts`: fetch and check images posted as plain links (not
  just attachments) from these hosts only. The bot never fetches an arbitrary URL found in a
  message — only hosts on this list — to avoid becoming an open URL-fetching proxy.
- `storage.database_path`: where the SQLite database (flood-detection state + per-server
  settings) lives.

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
