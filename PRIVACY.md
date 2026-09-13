# Privacy Policy — discord-anti-scam-bot

_Last updated: 2026-09-13_

This Privacy Policy explains what data the discord-anti-scam-bot Discord bot (the "Bot")
processes and why.

## 1. What the Bot processes

To do its job, the Bot needs to look at:

- **Image attachments** posted in the servers it's added to — downloaded in memory just long
  enough to compute a perceptual hash (a compact fingerprint of the image's visual content),
  then discarded. The original image bytes are **not stored**, unless a moderator explicitly
  adds them as a new scam reference via the `!scam add` command.
- **Message metadata** needed to act on a detection: the author's Discord user ID, the channel
  ID, and the message ID/timestamp.
- **Reference images**: screenshots of previously identified compromised accounts, kept on the
  disk of whoever hosts the Bot, used purely as a comparison baseline.

## 2. What the Bot stores, and for how long

- **Reference images and their fingerprints**: kept indefinitely (on the host's disk / in
  memory) until a moderator removes them with `!scam remove`. They are scam samples curated by
  moderators, not data collected about ordinary users.
- **Flood-detection activity** (which user posted which image fingerprint, in which channel,
  and when): kept **in memory only**, for a short rolling time window (a few minutes,
  configurable), purely to detect an account posting the same image across many channels in a
  short time. It is never written to disk and is cleared automatically, and entirely lost, on
  every restart of the Bot.
- **Detection logs**: when a detection occurs, the flagged image, the account and channel
  involved, and the action taken are posted to a moderation log channel chosen by the server
  operator. That log lives inside Discord itself, subject to the server's own permissions and
  Discord's own data retention — the Bot does not additionally copy it anywhere else.

The Bot does not keep a database of ordinary users' messages or images beyond what's described
above, and does not build profiles of users.

## 3. What the Bot does not do

- It does not read or store message text content beyond what's needed to detect and act on
  scam images (image attachments and the metadata above).
- It does not send any data to third-party services, analytics platforms, or advertisers.
- It does not sell or share data with anyone.
- It has no web dashboard or external database — everything it holds lives on the machine the
  server operator chooses to run it on.

## 4. Legal basis / who controls the data

The Bot is open-source software that a Discord server operator chooses to self-host and invite
to their own server(s). That operator decides which servers the Bot runs in and controls its
configuration (including the moderation log channel and reference images). For any given
server, the operator running that instance is the effective data controller for the processing
described here.

## 5. Your rights

If you believe the Bot has flagged you incorrectly, or you have questions about data it has
processed regarding your account, contact the operator of the server where it happened (they
control the moderation log and reference set), or open an issue on the project's GitHub
repository for questions about the Bot's code and behavior itself.

## 6. Changes to this policy

This Privacy Policy may be updated from time to time as the Bot evolves. Material changes will
be reflected in this document with an updated date at the top.

## 7. Contact

Questions can be raised by opening an issue on the project's GitHub repository.

See also the [Terms of Service](TERMS.md).
