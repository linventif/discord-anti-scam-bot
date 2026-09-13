# --- Build stage ---
FROM rust:1-bookworm AS builder
WORKDIR /app

# Cache dependency compilation separately from source changes.
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo "fn main() {}" > src/main.rs \
    && cargo build --release \
    && rm -rf src

COPY src ./src
# Force a rebuild of our own crate (the dummy main.rs above was already compiled
# and cached as part of the dependency-only build).
RUN touch src/main.rs && cargo build --release

# --- Runtime stage ---
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=builder /app/target/release/discord_anti_scam_bot /usr/local/bin/discord-anti-scam-bot
COPY config.example.toml ./config.example.toml

# reference/ (scam screenshots) and data/ (SQLite flood-detection db) are meant to
# be mounted as volumes so they persist across container recreations.
RUN mkdir -p reference data

ENTRYPOINT ["/usr/local/bin/discord-anti-scam-bot"]
