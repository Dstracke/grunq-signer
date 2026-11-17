# Store listing (copy for AMO / Chrome Web Store)

Everything needed to submit the built `dist/` folder. English is the primary
listing language; the UI itself follows the browser language (English
default/fallback, German bundled).

## Facts common to both stores

| Field | Value |
|---|---|
| Name | Grunq Signer |
| Version | 1.0.0 (`package.json` / `dist/manifest.json`) |
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
  banner, website, NIP-05, lightning address and bot flag, with a live
  preview and on-demand checks of the NIP-05 address and the lightning
  address; published to your relays. NIP-05 names on grunq.com can be
  requested right from the editor (signed claim, no account).
• Encrypted backup of all identities in one passphrase-protected file, and a
  warning when the same client name is connected twice (two devices).
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

## Screenshots (ready to upload)

All five are 1280×800 PNG (Chrome accepts 1280×800 or 640×400; AMO takes
these as-is), English UI, no user data:

| File | Shows |
|---|---|
| `store/screenshots/01-settings-identities.png` | Options page: identities with the active label + profile editor |
| `store/screenshots/02-popup.png` | Popup: identity, npub, QR/export button, passphrase + auto-lock |
| `store/screenshots/03-sign-approval.png` | Approval window: client, kind, time, content preview, Sign/Always/Deny |
| `store/screenshots/04-qr-export.png` | QR export: npub code, secret key behind the confirmation |
| `store/screenshots/05-audit-log.png` | Audit log with allowed/denied requests |

They were rendered from the real built UI (stubbed background data, no
secrets). A German set with the same five shots lives in
`store/screenshots/de/`. Regenerate after UI changes with the same 1280×800
viewport.

The step-by-step submission (fields, reviewer notes, permission
justifications, release notes) is in
[`release-1.0.0.md`](release-1.0.0.md).

## Before submitting – manual end-to-end check with the Grunq node

1. Load the built extension in Zen/Firefox (`about:debugging` → *Load
   Temporary Add-on* → `dist/manifest.json`) and create/import an identity.
2. In the Grunq node dashboard open the identity panel and click
   **“Mit Signer-Extension koppeln”**; the extension shows its pairing
   dialog (client name, npub, relays, source = page origin). Allow.
3. The dashboard confirms the pairing; restart the node with the stored
   `bunker://` URI (no secret) — the extension asks once more (secretless
   reconnect) and then signs.
4. Trigger a signature in the node (e.g. publish the stream announcement),
   check the options page → audit log for the entry.
5. Lock the extension (popup → “Lock now”): the node's next request must
   fail with `error:locked` and succeed again after unlocking.

## Submission notes

- Build the artifact: `npm run build && npm run package` →
  `web-ext-artifacts/grunq_signer-1.0.0.zip` (manifest at the zip root).
- Firefox (AMO): `npm run lint` first, then upload that zip (or the same
  build as source for the reviewer). The add-on id is `signer@grunq.com`; the signing key of the
  AMO account must stay stable so the id keeps working for self-distribution.
- Chrome Web Store: upload a zip of `dist/` contents; add the privacy policy
  URL from the table above; declare *no data collected*.
- Both stores need the privacy policy to be reachable before submission —
  `https://grunq.com/grunq-signer/privacy.html` is part of the landing page in
  the Grunq repository (`deploy/landing/grunq-signer/`).
- Release notes draft: “First public release: NIP-07 provider and NIP-46
  signer, NIP-49 passphrase protection with auto-lock, multiple identities,
  profile editor, QR export, audit log.”
