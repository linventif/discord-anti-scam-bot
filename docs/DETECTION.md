# Detection

How the bot decides an image is (probably) a known scam: perceptual-hash comparison against a
curated reference set, one behavioral heuristic (flood detection), and OCR of the image text
scored against known scam phrasing. No ML classification.

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

## OCR text detection (`ocr.rs`)

Hashing only recognizes an image it has (roughly) seen before. Scam waves reuse the same
*template* with new pixels each time — the fake MrBeast "crypto casino" tweet came back with
`sedowin.com` instead of `fayewin.com`, promo code `CASH` instead of `BET`, different amounts and
crops, and none of the four screenshots came within the hash threshold of the references (best
distances 20–45 for a threshold of 18). The wording, though, barely changes. So as a last check,
the image is run through `tesseract` and its text is scored: each rule is a phrase + weight, every
rule found adds its weight once, and a total ≥ `ocr.score_threshold` (6) is a detection.

- **Weights are set so no generic word flags on its own** ("bonus" 1, "casino" 2, "withdraw" 1):
  it takes one of the template's very specific phrases ("this post will be deleted", "was
  successfully" — the scam's own broken English —, "activate code for bonus", "каждому новому
  пользователю"...) or several weaker signals together. `ocr.rs::tests` has both the real OCR
  output of the scam screenshots (must flag) and ordinary gaming/crypto screenshots text (must
  not). Re-check both when touching the weights.
- **Cyrillic look-alike folding.** With `eng+rus`, tesseract regularly reads Latin text with a few
  Cyrillic homoglyphs mixed in ("Гат pleased", "ВАМК САВО"). `normalize()` folds those onto their
  Latin twin — applied to both the text and the patterns, so Russian patterns still match.
- **Color, not grayscale.** The image is decoded by us (same memory cap as hashing), downscaled
  to `max_dimension`, and piped to tesseract as an RGB PNG — tesseract never parses the untrusted
  original bytes. A naive grayscale conversion made tesseract miss the dark-theme popup text
  entirely, so don't "optimize" that back in.
- **Runs last and bounded**: only after the hash and flood checks, at most `max_concurrent`
  tesseract processes at a time, each killed after `timeout_seconds`. Roughly 0.5–2 s per
  screenshot.
- **Shells out to the CLI** instead of linking libtesseract: no C/C++ build dependency, and a
  missing binary just disables OCR at startup (warning logged, `/config show` says so).

## Retro-scan and review (`recent.rs`, `review.rs`)

A reference only helps from the moment it's added — but a scam wave is usually noticed a few
minutes in, after some posts already got through. So every image that triggers nothing has its
hash (not the image) kept in `RecentMedia` for `detection.retro_scan_minutes`, and
`Handler::add_reference` — the single path behind `!scam add`, the "Add to scam references"
context menu and the log's "➕" button — checks the new reference against that window with the
normal `match_threshold`. Matches are grouped per (guild, author) and go through `on_detection`
with *that* guild's settings: all their matching posts deleted, one sanction, one log.

Entries leave the window once acted on (`take_matches` removes them), and `on_detection` also
`forget`s every message it handles — without that, confirming a flood with "➕" would retro-match
the flood's earlier posts (recorded as harmless before the flood was detected, then deleted) and
sanction/log the author a second time.

**Author sweep.** The same window serves the other direction: when `on_detection` fires for an
author, `sweep_author` pulls that author's other entries in the same guild whose *message time*
(snowflake) is within ±`retro_scan_minutes` of the flagged message, and checks each against the
flagged image's hash, the references and — re-fetching the message, since only hashes are kept,
capped at 10 per detection — OCR. Matches are deleted as part of the same detection (same
sanction, same log). A compromised account that posted four different scam screenshots only
needs one of them to be caught.

Human review happens on the log messages: flood/OCR detections can be confirmed (→ reference) or
dismissed, reference-based ones can remove the reference. Buttons are gated server-side like
`!scam` (mod roles, else Manage Messages) — anyone who can see the log channel can *click* them.

## Tuning

| Setting | Effect of raising it | Effect of lowering it |
|---|---|---|
| `detection.match_threshold` | More false negatives (misses recompressed/edited variants of known scams) | More false positives (flags legitimate images that happen to be visually similar) |
| `flood.min_channels` | Needs a wider spray before flagging (fewer false positives, slower to catch) | Flags narrower reposting patterns (faster to catch, more prone to flagging a legitimately-shared image) |
| `flood.window_seconds` | Catches slower/more spread-out flooding | Only catches fast, bursty flooding |
| `flood.same_image_threshold` | Groups more distinct images together as "the same" for flood purposes | Requires near-identical images to count as a repeat |
| `ocr.score_threshold` | Needs more scam phrases in one image (fewer false positives, may miss a lone popup) | Flags on fewer phrases (catches more variants, more prone to flagging a legit screenshot) |
