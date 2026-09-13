# Architecture

A map of the codebase. For *how the detection logic actually works* (hashing, crop resistance,
flood detection, link fetching), see [DETECTION.md](DETECTION.md) — this doc is about how the
pieces fit together, not the algorithms inside them.

## Module map

| Module | Responsibility |
|---|---|
| `main.rs` | Startup: load config, open the reference store and flood DB, build the Discord client, run it. |
| `config.rs` | The `Config` struct tree (deserialized from `config.toml`) and the `Action` enum. |
| `configstore.rs` | `ConfigStore`: holds the live `Config` behind a lock, and persists changes back to `config.toml` in place (via `toml_edit`, touching only the changed key). |
| `handler.rs` | The `serenity::EventHandler` impl: `message` (the detection pipeline), `interaction_create` (dispatches to slash commands), `ready` (registers the global `/config` command). |
| `hashstore.rs` | `ReferenceStore`: loads reference images, computes perceptual hashes (including crop-resistant variants), compares an incoming image against the set. |
| `flood.rs` | `FloodDetector`: tracks recent image posts per user across channels in SQLite, to catch a compromised account cross-posting the same image everywhere. |
| `linkimage.rs` | `LinkImageFetcher`: extracts allow-listed image URLs from message text and downloads them (following one `og:image` hop for HTML pages like imgur galleries). |
| `slashconfig.rs` | Builds the `/config` command tree and handles both its execution and its autocomplete (the log-channel picker). |
| `commands.rs` | The legacy `!scam add/list/remove` prefix commands for managing reference images. |

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
             └─ FloodDetector::record_and_check          ──► cross-channel repost? → on_detection
                                                                        │
                                                                        ▼
                                                              delete message / timeout /
                                                              kick / ban (per config),
                                                              post evidence to the log channel
```

Every attachment and every extracted link is hashed and checked independently; the first one
that triggers a detection stops processing the rest of that message (see the `return`/`true`
propagation in `message()` and `evaluate_image()`).

## Config: read-mostly, written rarely

`Handler` holds `config: Arc<ConfigStore>`. On every message, `message()` takes one
`self.config.snapshot().await` (a cheap clone of the current `Config`) and uses that single
snapshot for the rest of the handler call — so a `/config` change mid-processing of one message
can't leave that call reading half-old, half-new values.

Writes (`ConfigStore::set_*` / `add_*` / `remove_*`) go the other way: update the in-memory
`Config` *and* patch the specific key in `config.toml` via `toml_edit`, so the file's comments
and everything else survive, and the value is still correct after a restart.

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
- **Flood-detection activity**: SQLite (`data/bot.sqlite3` by default), because it needs to
  survive a restart but is otherwise a small, short-lived (`flood.window_seconds`) rolling log —
  see [DETECTION.md](DETECTION.md#flood-detection) for the schema and why SQLite over a plain
  in-memory map.
- **Settings** (`config.toml`): see the "Config" section above.

None of these are a "server" the bot talks to over the network — everything lives on whatever
host/container runs the bot, which is why `reference/`, `data/`, and `config.toml` are all
bind-mounted in [docker-compose.yml](../docker-compose.yml) rather than baked into the image.
