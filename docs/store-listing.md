# Store listing (copy for AMO / Chrome Web Store)

Everything needed to submit the built `dist/` folder. English is the primary
listing language; the UI itself follows the browser language (English
default/fallback, German bundled).

## Facts common to both stores

| Field | Value |
|---|---|
| Name | Grunq Signer |
| Version | see `package.json` / `dist/manifest.json` |
| Summary (≤ 132 chars) | Nostr identity in your browser: NIP-07 provider and NIP-46 signer. Keys stay local, encrypted at rest, no account. |
| Category | Firefox: *Other* (or *Security & Privacy*) · Chrome: *Productivity* → *Developer Tools* is wrong; use *Productivity* |
| License | AGPL-3.0 |
| Homepage | https://grunq.com/grunq-signer/ |
| Privacy policy | https://grunq.com/grunq-signer/privacy.html (EN) · /datenschutz.html (DE) |
| Support / contact | contact@grunq.com |
| Source code | https://github.com/Dstracke/grunq-signer |
| Permissions | `storage` (identities, approvals, sessions, settings), `alarms` (keepalive + auto-lock tick) |
| Host permissions | none — network access happens through `WebSocket` to user-configured relays |
| Data collection | none (no telemetry, no account, no analytics) |

## Detailed description (EN)

```
Grunq Signer is a Nostr identity for your desktop browser: a NIP-07 provider
(window.nostr for approved sites) and a NIP-46 remote signer (bunker) for
other programs.

WHY
Mobile signer apps go to sleep; relays then queue requests for minutes. With
Grunq Signer the identity lives in the browser you already have open. The
Grunq streaming node, other NIP-46 clients and web apps in the same browser
all use the same key — which never leaves the extension background.

WHAT IT DOES
• window.nostr for approved sites: public key, event signing, NIP-04/NIP-44
  encrypt/decrypt. Every signature is confirmed in a separate window that
  always shows the site origin.
• Bunker:// invitations and nostrconnect:// pairing for other devices and
  programs (NIP-46), including the Grunq node.
• Optional passphrase protection (NIP-49 ncryptsec): the decrypted key lives
  in memory only and is dropped after a browser restart or the configured
  idle time (auto-lock).
• Multiple identities (for example a streamer key and a chat key) with
  per-identity sessions and profile.
• Public profile (kind 0) editor: name, display name, about, picture,
  NIP-05 and lightning address, published to your relays.
• Identity export as QR codes (npub openly, nsec only after an explicit
  confirmation) to move an identity to a phone.
• Audit log of the last answered requests (method, client, result) — no
  message contents.

PRIVACY
No account, no telemetry, no analytics, no cookies, no remote configuration.
The only network traffic goes to the Nostr relays you configure (default
wss://relay.grunq.com, removable). Keys are stored only in the browser's
extension storage and can be encrypted with your passphrase.

Grunq Signer is free software (AGPL-3.0) and works with any Nostr app or
client; it is not tied to the Grunq node.
```

## Screenshot checklist (1280×800 or 640×400; Chrome needs ≥ 1)

1. Popup with an identity and the “Security” card (passphrase/auto-lock).
2. Options page: identities + profile.
3. Approval dialog for a signature (origin, event kind, preview).
4. QR export panel (npub/nsec) — the secret blurred or hidden.
5. Audit log with a few entries.

## Submission notes

- Firefox (AMO): `npm run build` then `npm run lint`; zip the **contents of
  `dist/`** (manifest at the zip root) or upload `dist/` as the source with
  `web-ext build`. The add-on id is `signer@grunq.com`; the signing key of the
  AMO account must stay stable so the id keeps working for self-distribution.
- Chrome Web Store: upload a zip of `dist/` contents; add the privacy policy
  URL from the table above; declare *no data collected*.
- Both stores need the privacy policy to be reachable before submission —
  `https://grunq.com/grunq-signer/privacy.html` is part of the landing page in
  the Grunq repository (`deploy/landing/grunq-signer/`).
- Release notes draft: “First public release: NIP-07 provider and NIP-46
  signer, NIP-49 passphrase protection with auto-lock, multiple identities,
  profile editor, QR export, audit log.”
