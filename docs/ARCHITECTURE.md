# Architecture

A map of the codebase. For *how the detection logic actually works* (hashing, crop resistance,
flood detection, link fetching), see [DETECTION.md](DETECTION.md) — this doc is about how the
pieces fit together, not the algorithms inside them.

## Module map

| Module | Responsibility |
|---|---|
| `main.rs` | Startup: load config, open the reference store / flood DB / guild-settings DB, build the Discord client, run it. |
| `config.rs` | `Config` (bot-wide settings, from `config.toml`), `GuildConfig` (per-guild settings, with sensible defaults), and the `Action` enum. |
| `configstore.rs` | `ConfigStore`: holds the live bot-wide `Config` behind a lock. Currently read-only at runtime — nothing in `Config` is editable via a command. |
| `guildstore.rs` | `GuildSettingsStore`: the per-guild counterpart, backed by SQLite (`guild_settings` table) instead of a file, since there can be many guilds each with their own row. |
| `handler.rs` | The `serenity::EventHandler` impl: `message` (the detection pipeline), `interaction_create` (dispatches to slash commands), `ready` (registers the global `/config` command). |
| `hashstore.rs` | `ReferenceStore`: loads reference images, computes perceptual hashes (including crop-resistant variants), compares an incoming image against the set. |
| `flood.rs` | `FloodDetector`: tracks recent image posts per user across channels (scoped to one guild) in SQLite, to catch a compromised account cross-posting the same image everywhere. |
| `ocr.rs` | `OcrScanner`: runs the `tesseract` CLI on an image and scores its text against weighted scam phrases, to catch new screenshots of a known scam template. Disabled (`None` in `Handler`) if tesseract is missing. |
| `linkimage.rs` | `LinkImageFetcher`: extracts allow-listed image URLs from message text and downloads them (following one `og:image` hop for HTML pages like imgur galleries). |
| `slashconfig.rs` | Builds the `/config` command tree and handles both its execution and its autocomplete (the log-channel picker). Every setting it touches is per-guild. |
| `review.rs` | The "Add to scam references" message context-menu command, and the review buttons on log messages (confirm scam / false positive / remove reference). Stateless: each button's `custom_id` carries what it needs. |
| `recent.rs` | `RecentMedia`: in-memory look-back window of recent image hashes (no bytes) that didn't trigger anything, for the retro-scan run by `Handler::add_reference` whenever a reference is added. |
| `commands.rs` | The legacy `!scam add/list/remove` prefix commands for managing reference images (shared across guilds, see "Multi-guild" below). |

## Data flow: a message arrives

```
Discord gateway
      │
      ▼
Handler::message(ctx, msg)
      │
      ├─ bot / DM / prefix-command? → short-circuit
      │
      ├─ exempt channel/role? → return
      │
      ├─ scan_attachments(msg.attachments)          ─┐
      ├─ scan_attachments(snapshot.attachments)      │  same helper, run once per
      │    for each msg.message_snapshots[i]         │  attachment list (own message,
      │    (a "forward" carries content here,        │  and each forwarded snapshot)
      │    not as real attachments)                 ─┘
      │
      └─ scan_links(msg.content / snapshot.content)
             │
             ▼
       evaluate_image(bytes)
             │
             ├─ ReferenceStore::hash_bytes → best_match  ──► known reference? → on_detection
             │
             ├─ FloodDetector::record_and_check          ──► cross-channel repost? → on_detection
             │                                                (+ delete the earlier posts)
             │
             ├─ OcrScanner::check (tesseract, slowest)   ──► scam phrasing? → on_detection
             │
             └─ nothing matched → RecentMedia::record (for a later retro-scan)

Handler::add_reference (!scam add, context menu, "➕" review button)
      ├─ ReferenceStore::add_from_bytes
      └─ RecentMedia::take_matches → on_detection per (guild, author), with that guild's settings
                                                                        │
                                                                        ▼
                                                              delete message / timeout /
                                                              kick / ban (per config),
                                                              post evidence to the log channel
```

Every attachment and every extracted link is hashed and checked independently; the first one
that triggers a detection stops processing the rest of that message (see the `return`/`true`
propagation in `message()` and `evaluate_image()`).

## Multi-guild: bot-wide vs. per-guild settings

This bot runs in more than one Discord server (guild) at once, and each server's admins expect
their own independent settings — a log channel, sanction, and exempt roles/channels configured in
Server A must never affect Server B. That split runs through the whole config layer:

- **Bot-wide** (`Config`, `config.toml`, `ConfigStore`): `bot.prefix`, `detection.*`, `flood.*`,
  `links.*`, `storage.*`. Genuinely the same for every guild — these are operational/tuning knobs
  for the deployment, not something an individual server's admin should be able to change (there's
  no slash command exposing them).
- **Per-guild** (`GuildConfig`, SQLite `guild_settings` table, `GuildSettingsStore`):
  `log_channel_id`, `action`, `timeout_minutes`, `mod_role_ids`, `exempt_role_ids`,
  `exempt_channel_ids`. Keyed by `guild_id`; an unconfigured guild gets `GuildConfig::default()`
  until an admin runs `/config`. A single TOML file doesn't fit "one row per guild" well, hence
  SQLite here instead of `config.toml` even though it's still "config".

`Handler::message()` fetches both once per message — `self.config.snapshot().await` (bot-wide)
and `self.guild_settings.get(guild_id.get()).await` (this guild's) — and passes them down
together, so a `/config` change mid-processing of one message can't leave that call reading
half-old, half-new values, and one guild's settings can never leak into another's.

The **reference image set** (`reference/`) is the one deliberate exception: it's shared across
every guild by design (see [DETECTION.md](DETECTION.md)) — a scam screenshot flagged via `!scam
add` on one server is recognized on all of them, on the theory that a known scam template is a
known scam template regardless of which server first saw it. `commands.rs`'s `!scam` commands are
still guild-scoped for *authorization* (which mod role/Administrator can run them), just not for
the data they operate on.

`FloodDetector` is scoped by guild too (`flood_posts.guild_id`) for the same reason: without it, a
user who happens to be a member of two of the bot's servers could trip a "cross-channel flood"
alert by posting in unrelated channels of two *different* servers, which isn't the pattern this
heuristic is meant to catch.

## Slash commands: global, not per-guild

`/config` is registered globally (`Command::set_global_commands`) rather than per-guild. It was
originally per-guild (registered in the `ready` handler for each guild in `ready.guilds`), but
that only fires once per gateway connection — a guild the bot rejoins later (e.g. removed and
re-added) never got the command back without a full process restart. Global registration doesn't
have that problem, at the cost of the well-known Discord quirk that a *new* global command can
take up to ~1 hour to fully propagate to every client on first creation (updates to an existing
command are typically much faster).

## Persistence

- **Reference images** (`reference/`): plain files on disk, hashed on load and on `!scam add`.
  This *is* the persistence layer — no database involved.
- **Flood-detection activity** and **per-guild settings**: both SQLite, both in
  `data/bot.sqlite3` by default (two separate tables, two separate connections — see
  `FloodDetector` and `GuildSettingsStore`). Flood data needs to survive a restart but is
  otherwise a small, short-lived (`flood.window_seconds`) rolling log; see
  [DETECTION.md](DETECTION.md#flood-detection) for its schema and why SQLite over a plain
  in-memory map. Per-guild settings need SQLite for the more basic reason that "one row per
  guild" doesn't map onto a single TOML file at all.
- **Bot-wide settings** (`config.toml`): see "Multi-guild" above.

None of these are a "server" the bot talks to over the network — everything lives on whatever
host/container runs the bot, which is why `reference/`, `data/`, and `config.toml` are all
bind-mounted in [docker-compose.yml](../docker-compose.yml) rather than baked into the image.
