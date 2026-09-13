# Terms of Service — discord-anti-scam-bot

_Last updated: 2026-09-13_

These Terms of Service ("Terms") govern the use of the discord-anti-scam-bot Discord bot (the
"Bot"). By adding the Bot to a Discord server or otherwise interacting with it, you agree to
these Terms.

## 1. What the Bot does

The Bot is an automated moderation tool that:

- Scans image attachments posted in servers it has been added to.
- Compares them against a set of reference images (known scam/compromised-account
  screenshots) and against recent posting activity, to detect likely scam content.
- Automatically deletes messages it identifies as matching, and may time out, kick, or ban
  the associated account, depending on how the server operator has configured it.
- Posts a log of each detection (the flagged image, the account and channel involved, and
  the action taken) to a moderation channel chosen by the server operator.

## 2. No warranty

The Bot is provided "as is", without warranty of any kind, express or implied. Detection is
based on automated image comparison and heuristics; it can produce **false positives**
(legitimate content wrongly flagged) or **false negatives** (scams not detected). The Bot's
operator and maintainers make no guarantee of accuracy, availability, or fitness for any
particular purpose.

## 3. Limitation of liability

To the fullest extent permitted by law, the Bot's operator and the project's maintainers are
not liable for any direct, indirect, incidental, or consequential damages arising from the use
of, or inability to use, the Bot — including moderation actions taken automatically (message
deletion, timeout, kick, or ban) based on a false positive.

## 4. Server operator responsibility

Whoever adds the Bot to a Discord server is responsible for configuring it appropriately (the
action taken on detection, exempt roles/channels, and the moderation log channel) and for
reviewing its moderation log. The Bot acts automatically based on that configuration; the
server operator remains responsible for moderation decisions on their server.

## 5. Acceptable use

You may not use the Bot to violate Discord's own Terms of Service or Community Guidelines, to
harass users, or to interfere with the Bot's normal operation (e.g. attempting to abuse its
commands or flood it with requests).

## 6. Open source

The Bot's source code is publicly available. Anyone may self-host their own instance of the
Bot; these Terms apply to any given deployment of it, with that deployment's operator
responsible for their own instance.

## 7. Changes to these Terms

These Terms may be updated from time to time. Continued use of the Bot after a change
constitutes acceptance of the updated Terms.

## 8. Contact

Questions about these Terms can be raised by opening an issue on the project's GitHub
repository.

See also the [Privacy Policy](PRIVACY.md).
