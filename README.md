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

Spec phase, **M1 (NIP-07 core) implemented**: key import/generation,
`window.nostr` injection with per-origin approvals, per-sign confirmation
dialogs, NIP-04/NIP-44 encrypt/decrypt, developer test page. NIP-46 signer
(relay pool, bunker/nostrconnect pairing) is planned for M2; profile editor
and ncryptsec at-rest encryption for M3.

The full specification lives in
[`docs/browser-extension-spec.md`](docs/browser-extension-spec.md)
(architecture, NIP-07 layer, NIP-46 signer layer, security, test plan,
milestones M1–M4).

## Development

Requirements: Node.js ≥ 20.

```bash
npm install
npm run build   # bundles into dist/
npm test        # crypto tests against official NIP-44 vectors + BIP-173
```

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
