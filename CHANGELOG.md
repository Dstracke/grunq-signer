# Changelog

All notable changes to Grunq Signer. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); the project uses
semantic versioning.

## [Unreleased]

### Changed

- **Mindestversionen im Manifest:** Firefox Desktop 140 (statt 128), Firefox
  für Android 142. Ab Firefox 140 ist `data_collection_permissions` bekannt;
  mit `strict_min_version = 128` hat AMO die Datenerklärung als
  „nicht unterstützt" markiert. `gecko_android.strict_min_version` = 142
  beseitigt dieselbe Warnung für Android.

## [1.0.0] – 2026-11-17

First public release. A browser extension that is both a NIP-07 provider
(`window.nostr`) and a NIP-46 remote signer (bunker).

### Added

- **NIP-07 provider** for approved sites: `getPublicKey`, `signEvent`,
  `nip04.encrypt/decrypt`, `nip44.encrypt/decrypt`, `getRelays`; per-origin
  approvals with a confirmation window that always shows the site origin.
- **NIP-46 signer**: `bunker://` invitations, `nostrconnect://` pairing
  (including pairing deep links from web pages), session registry with
  revocation, `sign_event` approvals, per-kind permissions, decrypt gate,
  `ping`/`get_public_key`/`get_relays`/`switch_relays`, reconnect-on-wake
  via keepalive alarm.
- **NIP-49 passphrase protection** (`ncryptsec`, scrypt +
  XChaCha20-Poly1305): the decrypted key lives in memory only and is gone
  after a browser restart; export of the `ncryptsec` backup (text + QR).
- **Auto-lock** after inactivity (configurable, can be disabled); real
  NIP-07/NIP-46 traffic counts as activity.
- **Session idle policy**: remembered per-kind permissions expire after 30
  minutes without traffic (the paired session stays, the next signature asks
  once again).
- **Pairing rate limit**: five failed pairing/connect attempts per client or
  page within ten minutes stop further approval windows.
- **Multiple identities** with labels, per-identity NIP-46 sessions and
  profile; switching restarts the signer with the new key.
- **Public profile editor** (kind 0: name, display_name, about, picture,
  banner, website, nip05, lud16, bot flag) with URL validation, a live
  preview, publishing to the configured relays, loading back and NIP-09
  deletion; re-publishes on start to relays that lost the profile.
- **Profile checks on demand**: lud16 resolves the LNURL-pay endpoint (amount
  range, zap support), NIP-05 fetches `.well-known/nostr.json` and compares
  the published key with the identity. Both are https-only, size/time-limited
  and never run in the background.
- **NIP-05 claim for grunq.com**: the profile card checks name availability,
  signs a claim with the identity and prepares an e-mail to the operator;
  `tools/nip05-claim.mjs` verifies the signature (max. 7 days old, refuses
  names of other keys) and updates `nostr.json` atomically.
- **QR export** of npub (public) and nsec (behind an explicit two-step
  confirmation) to move an identity to a phone.
- **Encrypted backup**: all identities (labels + keys) and their profiles in
  one passphrase-sealed file; import merges by public key.
- **Multi-device warning**: the pairing dialog and the session list flag two
  connected clients with the same name (likely the same identity on a second
  device) so they do not overwrite each other's announcements.
- **Audit log** of the last answered requests (method, client, time,
  result) with per-source filtering; no message contents.
- **Options page** for identities, profile, pairing, relays, approvals
  (per-kind revoke), bunker sessions and the audit log.
- Localization follows the browser language, English is the
  default/fallback locale, German is bundled; locale parity is enforced by
  tests.
- Bundled `qrcode-generator` (MIT) for locally rendered QR codes.

### Security

- Content scripts never see key material; pages receive signed results only.
- Decryption requires a per-request confirmation; unknown NIP-46 clients
  need an explicit approval, secretless reconnects included.
- No telemetry, no account, no cloud; the only network traffic goes to the
  relays the user configures.
