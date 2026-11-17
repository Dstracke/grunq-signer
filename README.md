# Grunq Signer

Browser extension as a Nostr identity source: a **NIP-07 provider**
(`window.nostr` for approved sites) **and a NIP-46 signer** (bunker) for remote
clients — turning the desktop browser into a signer app: the nsec lives in the
extension's storage and never leaves the extension background.

Website: **https://grunq.com/grunq-signer/** · Source:
**https://github.com/Dstracke/grunq-signer** · Contact:
**contact@grunq.com**

First-class target is **Firefox/Gecko** (and thereby the Zen browser);
Chromium runs through the same code path. The default connect relay is the
Grunq bootstrap relay `wss://relay.grunq.com` (editable, no cloud
requirement); the public user profile (kind 0) is managed in the extension
and published to the allow-listed relays.

The UI language follows the browser: popup, approval dialogs, options page,
error texts and the manifest strings all go through the WebExtension i18n
mechanism (`_locales/`). **English is the default and fallback locale**
(`default_locale: en`), German is bundled as well; a French (or any other)
browser therefore gets English, a German browser gets German.

Selection order (WebExtension standard): exact browser locale (`de-DE`),
regionless (`de`), scriptless, then `default_locale`. Adding a language means
adding one `_locales/<code>/messages.json` with the same keys — `npm run
i18n:check` (also part of `npm test`) fails the build if a locale misses a key,
has an empty message or an undeclared `$PLACEHOLDER$`.

## Status

**Version 1.0.0 – first public release.** A browser extension that is both a
NIP-07 provider (`window.nostr`) and a NIP-46 remote signer (bunker).

- **NIP-07**: approved sites get `window.nostr`; every signature is confirmed
  with the site origin, remembered event kinds are configurable per site.
- **NIP-46**: `bunker://` invitations, `nostrconnect://` pairing (including
  deep links and the Grunq node handshake), session registry with revocation,
  per-kind permissions and a decrypt gate.
- **Key protection**: optional NIP-49 passphrase encryption (`ncryptsec`),
  keys in memory only, auto-lock after inactivity, QR export of npub/nsec,
  `ncryptsec` backup. Remembered NIP-46 permissions expire after 30 minutes
  idle; repeated failed pairings are rate-limited (5 per 10 minutes).
- **Multiple identities** with per-identity sessions and profile; public
  kind-0 profile editor with relay publishing and NIP-09 deletion; an
  encrypted backup file for all identities (export/import).
- **Audit log**, options page, de/en UI following the browser language.

`npm run package` produces the store artifact
(`web-ext-artifacts/grunq_signer-1.0.0.zip`); listing copy, screenshots and
submission notes live in [`docs/store-listing.md`](docs/store-listing.md).
Changes are listed in [`CHANGELOG.md`](CHANGELOG.md).

The full specification lives in
[`docs/browser-extension-spec.md`](docs/browser-extension-spec.md)
(architecture, NIP-07 layer, NIP-46 signer layer, security, test plan,
milestones M1–M4).

## Development

Requirements: Node.js ≥ 20.

```bash
npm install
npm run build   # bundles into dist/
npm test        # crypto + NIP-46 tests (E2E block runs against a real relay)
```

The NIP-46 end-to-end test pairs a mini client (same wire protocol as the
Grunq node) against the signer core over a real relay — by default
`ws://localhost:7777` (a local nostr-rs-relay). Override with
`RELAY_WS=wss://…`; the block is skipped when the relay is unreachable,
`FORCE_E2E=1` turns failures into errors.

Install from `dist/` until the store listings are live (see
[`docs/store-listing.md`](docs/store-listing.md)):

- **Firefox/Zen:** `about:debugging#/runtime/this-firefox` → *Load Temporary
  Add-on…* → pick `dist/manifest.json`.
- **Chromium:** `chrome://extensions` → enable developer mode → *Load
  unpacked* → pick the `dist/` directory.

`npm run lint` checks the built extension with `web-ext`; CI
(`.github/workflows/ci.yml`) runs build, tests and the lint step on every
push.

### Testing the NIP-07 surface

Serve the developer test page over plain HTTP and open it in the same
browser profile:

```bash
python3 -m http.server 8777
# then open http://localhost:8777/test/page.html
```

The page calls `getPublicKey`, `getRelays`, `signEvent` (kind 1) and does
nip04/nip44 roundtrips. The first call opens an approval dialog; every
signature needs a separate confirmation.

### Testing the NIP-46 signer (bunker)

Open the popup and press **Create invitation** — it shows a `bunker://…`
URI that any NIP-46 client can use (e.g. the Grunq dashboard's "Connect
identity"). Active connections are listed below with a remove button; the
**Relays** card edits the relay set (one `wss://…` per line, the Grunq
bootstrap relay is the default).

Every incoming `sign_event` opens a confirmation dialog showing the
connecting client and the event preview. Background wake-ups reconnect the
relay subscriptions automatically (keepalive alarm, one minute).

### Moving an identity with the QR codes

The identity card has a **QR code / export** button: it shows the npub as a
QR code (public, safe to share) and — after an explicit second confirmation
showing the warning — the nsec. Both codes are generated locally with the
bundled `qrcode-generator`; nothing is sent anywhere. Scan the nsec code with
a signer app on the phone (NIP-46 client) or import the string there by hand.
The secret is dropped from the popup as soon as the panel is collapsed.

### Settings page and audit log

The popup keeps the quick actions (unlock, QR export, invitations); the
options page (**Settings** in the popup header, or the browser's extension
settings) holds the writable parts:

- **Identities** — add (`nsec`/`ncryptsec` + label) or create another key,
  activate it, remove it. Sessions and the profile are kept per identity;
  switching stops and restarts the NIP-46 signer with the new key.
- **Profile** — the public kind-0 event of the active identity, published to
  the relay list; publishing/deleting requires an unlocked identity.
- **Pairing** — paste a `nostrconnect://` invitation, or open the page as
  `options/options.html?nostrconnect=…` for a prefilled pairing card.
- **Relays** — the allow-list used for invitations, NIP-07 `getRelays` and
  profile publishes.
- **Site approvals** — each origin with the event kinds it may sign without
  asking; the `×` on a kind chip brings back the confirmation for that kind
  only, "Revoke site" removes the origin completely.
- **Bunker connections** — active NIP-46 clients with name, npub and relays,
  removable.
- **Audit log** — the last requests the extension answered (time, source,
  method + kind, ok/denied with error code), filterable per client or site
  and clearable. It never stores message contents or keys.

### Publishing the profile

The **Profile** section edits the public kind-0 event: `name`, `display_name`, `about`, `picture`, `nip05` and
`lud16`. **Publish profile** signs it with the identity and sends it to the
configured relay list (including `relay.grunq.com` when it is there); the
fields are saved locally first, so a relay problem never loses your input.
**Load from relays** pulls the newest own profile back (works while locked —
reading needs no key), **Delete profile** sends a NIP-09 request with `e` and
`a` tags and clears the local copy. Publishing and deleting need an unlocked
identity. After a browser start the extension checks each relay once (at most
hourly) and republishes the local profile only where it is missing —
**Check relays** runs that repair on demand.

### Passphrase protection and auto-lock

The **Security** card encrypts the stored key with a passphrase (NIP-49,
`ncryptsec`: scrypt + XChaCha20-Poly1305). The decrypted key then lives only
in `storage.session` (memory) and is gone after a browser restart; the
passphrase itself is never stored. The card also exports the `ncryptsec` as
a copyable string and QR code — keep that backup somewhere safe, it is the
only way back if the passphrase is forgotten.

With protection enabled the signer locks after the configured idle time
(default 30 minutes, adjustable, `autoLock` can be switched off). Real
NIP-07/NIP-46 traffic counts as activity, so a running stream keeps itself
unlocked while an idle browser locks. A locked signer answers `error:locked`,
the NIP-46 subscriptions pause (a Grunq node simply waits, like with a
sleeping signer phone) and the popup only shows the unlock field. An
`ncryptsec` backup can be imported as the identity — the import field asks
for its passphrase.

## Contact and links

- Landing page (store listing target): <https://grunq.com/grunq-signer/>
- Privacy policy: <https://grunq.com/grunq-signer/privacy.html>
  (German: <https://grunq.com/grunq-signer/datenschutz.html>)
- E-mail: <contact@grunq.com> — for security reports please read
  [`SECURITY.md`](SECURITY.md) first.
- Source: <https://github.com/Dstracke/grunq-signer>

## Related projects

- **Grunq node** — the decentralized live-streaming client (Go) that this
  extension is the browser identity for: <https://grunq.com>
- The extension's design background lives in the specification next to this
  README ([`docs/browser-extension-spec.md`](docs/browser-extension-spec.md)).

## License

GNU Affero General Public License v3.0 (AGPL-3.0), see
[`LICENSE`](LICENSE) — same as the Grunq node.

Exceptions:

- **Inter Tight** (`src/fonts/InterTight-Variable.woff2`, used by the popup
  and approval dialog) is licensed under the SIL Open Font License 1.1 —
  same bundled font as the Grunq node web UI. The license text is available
  in the Grunq repository (`THIRD_PARTY_NOTICES.md`).
- **noble libraries** (`@noble/curves`, `@noble/hashes`, `@noble/ciphers`,
  MIT) are bundled into the build; see their upstream repositories.
- **qrcode-generator** (`src/vendor/qrcode-generator.cjs`, MIT, Copyright
  (c) 2009 Kazuhiko Arase, <https://github.com/kazuhikoarase/qrcode-generator>)
  renders the identity QR codes in the popup; the file is shipped unchanged
  (same file the Grunq node serves as `web/static/js/qrcode-generator.js`).
