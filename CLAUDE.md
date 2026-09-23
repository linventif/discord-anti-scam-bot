# CLAUDE.md

Guidance for Claude Code (or any AI assistant) working in this repository.

## What this is

A Discord bot (Rust, `serenity`) that detects reposted scam screenshots (compromised-account
Nitro/crypto scams) via perceptual image hashing, plus a cross-channel flood heuristic, and
auto-moderates (delete/timeout/kick/ban) based on config. See [README.md](README.md) for the
user-facing feature list and [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) +
[docs/DETECTION.md](docs/DETECTION.md) for how it actually works — read those before making
non-trivial changes instead of re-deriving the design from the source.

## Commands

```bash
cargo build              # dev build
cargo build --release    # what actually gets deployed
cargo test                # 27 tests as of writing; keep them passing
cargo check               # fast type-check while iterating
```

No `rustfmt`/`clippy` gate in CI yet — match the existing style in whatever file you're editing.

Building needs a C compiler (`cc`/`gcc`) on PATH — `rusqlite`'s `bundled` feature compiles SQLite
from source. If a fresh environment fails with `linker 'cc' not found`, that's the fix (e.g.
`apt install build-essential`), not a code problem.

OCR (`ocr.rs`) shells out to the `tesseract` CLI at runtime (installed in the Docker image and in
CI). Without it locally, OCR is simply disabled and `ocr::tests::reads_a_real_scam_screenshot`
skips itself — install `tesseract-ocr tesseract-ocr-eng tesseract-ocr-rus` to run it for real.

## Config: bot-wide (TOML) vs. per-guild (SQLite) — don't mix these up

This bot runs in multiple Discord servers at once. **Never add a per-server-meaningful setting
(a channel ID, a role ID, anything an individual server's admin should control) to `Config` /
`config.toml`.** That file is bot-wide — the same value applies to every guild simultaneously.
This was a real bug once (see `docs/ARCHITECTURE.md#multi-guild-bot-wide-vs-per-guild-settings`):
`log_channel_id` and the moderation settings used to live in `config.toml`, so `/config` in one
server silently overwrote another server's settings.

- Bot-wide, deployment-level settings → `Config` (`config.rs`) / `config.toml` /
  `config.example.toml` / `ConfigStore` (`configstore.rs`). Currently nothing here is
  runtime-editable.
- Per-guild settings → `GuildConfig` (`config.rs`) / SQLite `guild_settings` table /
  `GuildSettingsStore` (`guildstore.rs`), keyed by `guild_id`. This is what `/config`
  (`slashconfig.rs`) reads and writes.

`config.toml` itself is still split in two: `config.example.toml` (committed, generic template)
vs. `config.toml` (gitignored, the actual live config for whatever instance is running). Tests
that need a config file copy `config.example.toml` to a throwaway temp path rather than touching
this one.

If you add a new bot-wide field, add it to `config.example.toml` too (with an explanatory comment
— this is the only place most users will ever see the option). If you add a new per-guild field,
add a column to `guild_settings` (`guildstore.rs`'s `CREATE TABLE`/`read_row`/`write_row`), a
default in `GuildConfig::default()`, and wire it into `/config` (`slashconfig.rs`) — not into
`config.toml` at all.

## Testing gotchas (already hit once, worth not re-discovering)

- **Solid-color test images are useless for hash tests.** The gradient-based perceptual hash is
  invariant to constant brightness — every solid color hashes the same. Use `noise_hash()` (see
  `flood.rs::tests`) or an actual varied image when a test needs two images to hash *differently*.
- **`reference/image.jpg` and `reference/image8.jpg` are near-duplicates** of each other (same
  underlying screenshot). Don't use `image.jpg` as a "this should uniquely match X" test target —
  use `image3.jpg` or `image4.jpg` instead, which don't have a duplicate in the set.
- Async tests that touch SQLite can use `":memory:"` as the path (`FloodDetector::open`,
  `GuildSettingsStore::open`) — no temp-file cleanup needed for those.
- **Any SQLite schema change needs a migration, not just an updated `CREATE TABLE IF NOT
  EXISTS`.** That statement is a no-op against a table that already exists with an older schema —
  it will NOT add a missing column, and a later `CREATE INDEX` on that column then fails on any
  pre-existing database file. This broke a real deployment once when `guild_id` was added to
  `flood_posts`. The fix (see `FloodDetector::open`) is `ALTER TABLE ... ADD COLUMN ...` guarded
  with `let _ =` (it errors harmlessly with "duplicate column" on a table that already has the
  column, including one just freshly created) run *before* creating any index that references the
  new column. `flood.rs::tests::opens_a_pre_multi_guild_database` is the regression test — write
  an equivalent one for any future schema change.

## Operational notes

- The bot reads `DISCORD_TOKEN` from the environment (`.env` via `dotenvy`, or a real env var in
  Docker/CI) — never hardcode a token or put one in a file that isn't gitignored.
- `/config` is a **global** slash command (`Command::set_global_commands`, not per-guild) — see
  [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md#slash-commands-global-not-per-guild) for why. Don't
  revert to per-guild registration without re-reading that section; it was a deliberate fix for a
  real bug (commands disappearing after remove/re-add).
- CI (`.github/workflows/ci.yml`) runs `cargo build && cargo test` on every push/PR to `main`.
  Releases (`.github/workflows/release.yml`) are triggered by pushing a `vX.Y.Z` tag — see
  [README.md#releases](README.md#releases).

## Security-sensitive areas — be deliberate here

- `linkimage.rs`'s host allow-list is what stops this bot from being an open URL-fetching proxy
  (SSRF). Never add a code path that fetches a URL from message content without checking it
  against `allowed_hosts` first.
- Any new Discord permission check (slash command gating, moderation actions) should follow the
  existing pattern: Discord-side gate (`default_member_permissions`) *and* a server-side check
  (defense in depth — a server admin can loosen the Discord-side gate in Integration Settings).
