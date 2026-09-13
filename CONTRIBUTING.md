# Contributing

Thanks for considering a contribution to discord-anti-scam-bot. This is a small, focused
project, so the process is intentionally lightweight.

## Getting set up

You need a Rust toolchain (stable, edition 2021) and a C compiler (`cc`/`gcc` — needed to build
`rusqlite`'s bundled SQLite). Docker is optional, only needed if you want to test the container
build.

```bash
git clone https://github.com/linventif/discord-anti-scam-bot.git
cd discord-anti-scam-bot

cp .env.example .env                  # add your own test bot's DISCORD_TOKEN
cp config.example.toml config.toml    # config.toml is gitignored, safe to edit freely

cargo build
cargo test
```

To actually run the bot against a real (test) Discord server, see the [README](README.md)'s
Install/Discord setup sections — you'll want your own throwaway bot application for this so you
don't need write access to anyone else's server.

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for a map of the codebase and
[docs/DETECTION.md](docs/DETECTION.md) for how the detection pipeline (hashing, crop resistance,
flood detection, link fetching) actually works — read these before making non-trivial changes.

## Making a change

1. Open an issue first for anything beyond a small fix (bug fix, docs, tests) — for new
   detection logic, new config options, or new commands, a quick discussion up front saves
   everyone rework.
2. Branch off `main`, keep the change focused on one thing.
3. Add or update tests for what you touched. The existing tests (`cargo test`) are a good
   reference for the patterns already in use, in particular:
   - `hashstore.rs`'s crop tests use two *distinct* reference images specifically to avoid the
     near-duplicate images already in `reference/` (`image.jpg`/`image8.jpg` are the same
     screenshot) — pick a target image deliberately if you add hash tests.
   - `flood.rs`'s tests use *noise* images, not solid colors — a solid-color image is a
     degenerate case for the gradient-based hash (every solid color hashes the same), so it
     can't tell two truly different images apart. Reuse `noise_hash()` for anything that needs
     two images to hash differently.
   - `configstore.rs`'s test copies `config.example.toml` to a throwaway temp path rather than
     touching the real `config.toml`.
4. `cargo build && cargo test` locally before opening a PR — CI (`.github/workflows/ci.yml`)
   runs the same thing on every push/PR.
5. Open a PR against `main`. Describe *why* the change is needed, not just what it does — that
   context is what's hard to reconstruct later from the diff alone.

## Code style

No enforced formatter/linter yet (no `rustfmt.toml` or clippy gate in CI) — match the style
already in the file you're editing. A few conventions used throughout the codebase:

- Comments explain *why*, not *what* — the code should read clearly enough that a comment
  restating it would be redundant. See existing modules for the level of detail expected.
- Config changes go through `ConfigStore` (`src/configstore.rs`), which edits `config.toml`
  surgically via `toml_edit` — touching only the changed key so comments and formatting
  elsewhere in the file survive. Don't reintroduce whole-file `toml::to_string` round-tripping,
  it would silently strip every comment in the file.
- Keep new dependencies to a minimum, and prefer ones already pulled in transitively when
  reasonable (check `cargo tree` before adding something new).

## Reporting bugs / false positives / false negatives

Open an issue with: what image or message triggered (or should have triggered) a detection, the
relevant `config.toml` values (`detection.match_threshold`, `flood.*`), and what actually
happened vs. what you expected. If it's a missed detection, attaching the image (or a link to
it) is the fastest way to get it fixed.

## Releasing

Maintainers only: pushing a `vX.Y.Z` tag triggers
[.github/workflows/release.yml](.github/workflows/release.yml), which builds a release binary,
publishes the Docker image to `ghcr.io/linventif/discord-anti-scam-bot`, and creates a GitHub
Release with auto-generated notes. See the [README](README.md#releases) for details.

## License

By contributing, you agree your contribution is licensed under the project's [MIT
License](LICENSE).
