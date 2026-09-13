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
cargo test                # 10 tests as of writing; keep them passing
cargo check               # fast type-check while iterating
```

No `rustfmt`/`clippy` gate in CI yet — match the existing style in whatever file you're editing.

Building needs a C compiler (`cc`/`gcc`) on PATH — `rusqlite`'s `bundled` feature compiles SQLite
from source. If a fresh environment fails with `linker 'cc' not found`, that's the fix (e.g.
`apt install build-essential`), not a code problem.

## Config: two files, not one

- `config.example.toml` — committed, generic template.
- `config.toml` — gitignored, the actual live config for whatever instance is running. Tests that
  need a config file copy `config.example.toml` to a throwaway temp path rather than touching
  this one (see `configstore.rs::tests`).

If you add a new config field, add it to **both** `config.example.toml` (with an explanatory
comment — this is the only place most users will ever see the option) and, if it's meant to be
changeable at runtime, wire it into `ConfigStore` (`src/configstore.rs`) and the `/config` slash
command (`src/slashconfig.rs`), not just `config.rs`'s struct.

## Testing gotchas (already hit once, worth not re-discovering)

- **Solid-color test images are useless for hash tests.** The gradient-based perceptual hash is
  invariant to constant brightness — every solid color hashes the same. Use `noise_hash()` (see
  `flood.rs::tests`) or an actual varied image when a test needs two images to hash *differently*.
- **`reference/image.jpg` and `reference/image8.jpg` are near-duplicates** of each other (same
  underlying screenshot). Don't use `image.jpg` as a "this should uniquely match X" test target —
  use `image3.jpg` or `image4.jpg` instead, which don't have a duplicate in the set.
- Async tests that touch SQLite can use `":memory:"` as the path (`FloodDetector::open`) — no
  temp-file cleanup needed for those.

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
