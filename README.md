# Grunq Signer

Browser extension as a Nostr identity source: a **NIP-07 provider**
(`window.nostr` for approved sites) **and a NIP-46 signer** (bunker) for remote
clients — turning the desktop browser into a signer app: the nsec lives in the
extension's storage and never leaves the extension background.

First-class target is **Firefox/Gecko** (and thereby the Zen browser);
Chromium runs through the same code path. The default connect relay is the
Grunq bootstrap relay `wss://relay.grunq.com` (editable, no cloud
requirement); the public user profile (kind 0) is managed in the extension
and published to the allow-listed relays.

The UI language (popup, dialogs, errors) follows the browser settings
automatically via the WebExtension i18n mechanism (`_locales/`, English +
German; manifest strings via `__MSG_…__`).

## Status

Spec phase, **M1 (NIP-07 core) implemented and verified**: key
import/generation, `window.nostr` injection with per-origin approvals,
per-sign confirmation dialogs, NIP-04/NIP-44 encrypt/decrypt, developer
test page. **M2 (NIP-46 signer) implemented**: relay pool over plain
WebSockets, `bunker://` invitations (popup), session registry with
revocation, `sign_event` confirmation dialog, reconnect-on-wake via
keepalive alarm, test-suite end-to-end against a real relay with a mini
NIP-46 client. Planned for M3: `nostrconnect://` pairing UI, kinds
whitelists, audit log, ncryptsec at-rest encryption, auto-lock, profile
editor.

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
Grunq node) against the signer core over `ws://archserver:7777` by
default — override with `RELAY_WS=...`, skip with an unreachable relay,
force with `FORCE_E2E=1`.

Load the built extension from `dist/`:

- **Firefox/Zen:** `about:debugging#/runtime/this-firefox` → *Load Temporary
  Add-on…* → pick `dist/manifest.json`.
- **Chromium:** `chrome://extensions` → enable developer mode → *Load
  unpacked* → pick the `dist/` directory.

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

## Related projects

- **Grunq node** (decentralized live streaming client in Go; this extension
  is its browser identity extension):
  `ssh://luku@192.168.0.99/home/luku/projekte/grunq.git`
- **Ideas repository** (roadmap; the extension idea is GQ-37):
  `ssh://luku@192.168.0.99/home/luku/projekte/ideen.git`
  (`grunq/GQ-37-browser-signer-extension.md`)

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
