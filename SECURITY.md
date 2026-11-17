# Security policy

## Reporting a vulnerability

Please **do not open a public issue** for security problems.

- E-mail: **contact@grunq.com** (subject: `Grunq Signer security`)
- If possible, include: affected version, browser (Firefox/Chromium) and OS,
  the steps to reproduce, and what an attacker gains.

You get an acknowledgement within a few days. Please give us time to ship a
fix before publishing details; a coordinated disclosure date can be agreed.

## Scope

In scope:

- Key handling (storage at rest, unlocking, passphrase derivation, memory
  lifetime of the decrypted key).
- NIP-07 injection and origin approval (bypassing approvals, injecting into
  the wrong world, leaking keys to pages).
- NIP-46 signer (session binding, pairing secrets, secretless reconnects,
  permission handling, decrypt gate).
- Output encoding in the popup/options/approval pages.

Out of scope:

- The browser itself (extension storage is readable by anyone with access to
  the profile — this is why passphrase protection and auto-lock exist).
- Relays you configure: they see the public events you publish and the
  source IP, which is inherent to Nostr.
- Wallet functions: the extension holds no wallet and cannot pay.

## Questions

General questions about the project can go to the same address or into a
regular issue.
