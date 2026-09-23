# Detection

How the bot decides an image is (probably) a known scam, without doing any OCR/ML classification
— it's all perceptual-hash comparison against a curated reference set, plus one behavioral
heuristic (flood detection).

## Perceptual hashing (`hashstore.rs`)

Every reference image, and every incoming image, gets reduced to a **256-bit fingerprint**
(`image_hasher`, `HashAlg::DoubleGradient`, 16×16) that's resistant to recompression and minor
resizing — two visually-similar images hash to a small Hamming distance apart, even if their
bytes are completely different. `ReferenceStore::best_match` finds the closest reference and
its distance; a match below `detection.match_threshold` (default 18, i.e. ~7% of the 256 bits)
counts as a detection.

### Crop resistance

A *global* perceptual hash (hash the whole image, once) is fragile to cropping: trim even a
sliver off one edge and the hash can change enough to dodge the threshold, because gradient-based
hashing looks at how brightness changes *between* regions of the image — shifting the crop
window shifts every one of those comparisons.

The fix (`ReferenceStore::crop_variants`) is to hash several *variants* of each image instead of
just one:

- the original, uncropped image,
- center + 4 corners at two mild ratios (0.85, 0.7) — catches "trimmed a thin border off one
  side",
- center-only at more aggressive ratios (0.55, 0.4) and thin strips (0.33×1.0, 1.0×0.33,
  0.5×1.0, 1.0×0.5) — catches someone keeping only the *middle* of a screenshot, which is
  usually where the actual scam message/content is, and cropping away the surrounding UI chrome.

`ImageVariants::min_dist` then compares **every** variant of the incoming image against **every**
variant of a reference and takes the minimum distance. This is `O(variants²)` per reference
comparison, but `variants` is small (~16) and hashing a 16×16 grid is cheap, so it's not a
performance concern at the reference-set sizes this bot is meant for (dozens to low hundreds of
images, not tens of thousands).

If you need to cover an even more aggressive crop than "middle third", add another `(width_ratio,
height_ratio)` pair to `crop_variants` — see `hashstore.rs::tests` for how to write a regression
test for a specific crop shape (the two existing tests cover an asymmetric partial crop and an
exact middle-third crop).

**Known gap**: this is still a *global* comparison per variant — it doesn't do local
feature-matching (like SIFT/ORB keypoints), so a sufficiently aggressive crop, rotation, or
heavy edit can still evade it. Catching that would mean a fundamentally different (and much
heavier) approach; the crop-variant trick is a pragmatic middle ground, not a complete defense.

## Flood detection (`flood.rs`)

Independent of the reference set: if the **same account** posts the **same image** (by hash, not
by matching a known reference) across `flood.min_channels` or more distinct channels within
`flood.window_seconds`, that's flagged too — a self-bot/webhook on a compromised account
typically blasts its scam into every channel it can see, which is a strong signal on its own even
before that specific image is a known reference.

This uses `hash.primary` only (the *uncropped* hash), not the crop variants — flood detection is
about literal reposts in a short window, not about evading detection through cropping, so the
extra cost of comparing every variant isn't worth it here.

### Why SQLite instead of an in-memory map

It used to be a plain `HashMap<UserId, Vec<Post>>`. That's simpler, but it means a bot restart
(redeploy, crash, `docker compose up -d --build`) forgets everything — a scammer mid-flood a
moment before a restart gets a clean slate. SQLite fixes that at low cost: the table
(`flood_posts`: `guild_id`, `user_id`, `channel_id`, `message_id`, `hash` as base64, `ts`) is small, short-lived
(`DELETE ... WHERE ts < cutoff` runs on every insert, so it never grows past the window), and
queries are a handful of rows per user — a plain `tokio::sync::Mutex<rusqlite::Connection>` is
fine here; there was no need to reach for a connection pool or a `spawn_blocking` actor pattern
for this volume of traffic.

## Link images (`linkimage.rs`)

Attachments aren't the only way an image reaches a channel — a plain link (e.g. to imgur) works
too, and Discord's own auto-embed preview isn't reliable enough to depend on (it's generated
asynchronously after the message is sent, and a scammer can suppress it entirely with
`<https://...>`). So the bot does its own extraction directly from the message text.

### The SSRF constraint

Blindly fetching every URL found in a message would make the bot an **open URL-fetching proxy**:
point it at `http://169.254.169.254/...` (cloud metadata) or an internal service and the bot
would dutifully fetch it. `LinkImageFetcher` only ever fetches a URL whose host is in
`links.allowed_hosts` (exact match or a subdomain of one) — there is no code path that fetches an
arbitrary URL from message content.

For a host that serves an HTML page rather than a direct image (e.g. `imgur.com/abc123`, as
opposed to `i.imgur.com/abc123.png`), it follows exactly **one** hop: fetch the page, look for an
`<meta property="og:image" ...>` tag, fetch *that* URL, and stop — no further redirects or hops
are followed, and the second fetch still goes through the same size cap (`MAX_BYTES`, 15 MiB) as
the first.

### Forwarded messages

A Discord "forward" carries the original message's content, including its attachments, in
`message.message_snapshots` — not as real attachments on the forwarding message. Both attachment
scanning and link scanning run once on the message itself and once per snapshot it carries (see
`Handler::scan_attachments` / `scan_links` and their call sites in `handler.rs::message`), so a
forwarded multi-image scam is checked exactly like a directly-posted one.

## Tuning

| Setting | Effect of raising it | Effect of lowering it |
|---|---|---|
| `detection.match_threshold` | More false negatives (misses recompressed/edited variants of known scams) | More false positives (flags legitimate images that happen to be visually similar) |
| `flood.min_channels` | Needs a wider spray before flagging (fewer false positives, slower to catch) | Flags narrower reposting patterns (faster to catch, more prone to flagging a legitimately-shared image) |
| `flood.window_seconds` | Catches slower/more spread-out flooding | Only catches fast, bursty flooding |
| `flood.same_image_threshold` | Groups more distinct images together as "the same" for flood purposes | Requires near-identical images to count as a repeat |
