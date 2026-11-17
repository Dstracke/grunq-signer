# Release 1.0.0 – Store-Einreichung

Alles, was für die Einreichung bei **addons.mozilla.org (AMO)** und im
**Chrome Web Store** gebraucht wird – inklusive Kopiervorlagen. Der Stand
ist reproduzierbar: Build, Tests und Lint sind im CI grün.

## Artefakt

```bash
npm ci
npm run build
npm test          # 91 Tests + 1 übersprungener Relay-E2E (lokal: RELAY_WS=…)
npm run lint      # web-ext: 0 Fehler (3 bekannte Warnungen)
npm run package   # -> web-ext-artifacts/grunq_signer-1.0.0.zip
```

| Feld | Wert |
|---|---|
| Datei | `web-ext-artifacts/grunq_signer-1.0.0.zip` |
| Größe | 164 KB (30 Dateien, `manifest.json` im ZIP-Root) |
| SHA-256 | `5e5e0be1821461fa61b40e0ea782e577e724da65b9ff03d39a26173aa52f872b` |
| Add-on-ID | `signer@grunq.com` |
| Lizenz | AGPL-3.0 |
| Datenschutz | https://grunq.com/grunq-signer/privacy.html (DE: `/datenschutz.html`) |
| Homepage | https://grunq.com/grunq-signer/ |
| Quellcode | https://github.com/Dstracke/grunq-signer |
| Support | contact@grunq.com |

## Screenshots

Alle 1280×800, englischer Satz in `store/screenshots/`, deutscher Satz in
`store/screenshots/de/`:

1. `01-settings-identities.png` – Options: Identitäten + Profil
2. `02-popup.png` – Popup: Identität, QR, Passphrase/Auto-Lock
3. `03-sign-approval.png` – Signatur-Bestätigung (Client, Kind, Inhalt)
4. `04-qr-export.png` – QR-Export (npub offen, nsec hinter Bestätigung)
5. `05-audit-log.png` – Audit-Log mit erlaubt/abgelehnt

## AMO (Firefox/Zen)

1. https://addons.mozilla.org/developers/ → **Submit a New Add-on** →
   *On this site* → ZIP hochladen.
2. Plattformen: **Firefox Desktop** (Android nicht nötig; die Extension
   nutzt `storage.session` und Alarme, die dort laufen, aber das ist nicht
   getestet).
3. **Name:** Grunq Signer
4. **Summary (EN):**
   ```
   Nostr identity in your browser: NIP-07 provider and NIP-46 signer. Keys stay local, encrypted at rest, no account.
   ```
   **Summary (DE):**
   ```
   Nostr-Identität im Browser: NIP-07-Provider und NIP-46-Signer. Schlüssel bleiben lokal, verschlüsselbar, kein Account.
   ```
5. **Description (EN)** – siehe `docs/store-listing.md`, Abschnitt
   "Detailed description".
6. **Kategorie:** Other (alternativ Security & Privacy)
7. **Support-E-Mail:** contact@grunq.com
8. **Privacy policy:** https://grunq.com/grunq-signer/privacy.html
9. **License:** AGPL-3.0 (im Formular „GNU Affero General Public License v3.0")
10. **Notes to reviewer (EN):**
    ```
    No remote code is used; the bundle is unminified (see dist/ in the source
    zip or the linked repository). To test:
    - Open the popup, create a new identity (all data stays local).
    - Visit https://grunq.com/grunq-signer/ → "documentation" links the
      developer test page pattern; or use any NIP-07 test page to call
      window.nostr.getPublicKey()/signEvent().
    - NIP-46: the popup has "Create invitation"; any NIP-46 client can pair.
    The extension opens WebSockets only to the relays listed under Settings
    (default wss://relay.grunq.com, editable/removable). No telemetry, no
    analytics, no accounts.
    ```
11. **Data collection:** "This add-on collects no data" (manifest declares
    `data_collection_permissions.required = ["none"]`).
12. Nach Freigabe: Installations-Button-Link auf der Landing-Page
    (`/grunq-signer/`) eintragen und `README`-Link ergänzen.

## Chrome Web Store

1. https://chrome.google.com/webstore/devconsole → **New item** → ZIP
   hochladen (Entwicklerkonto einmalig 5 USD).
2. **Name:** Grunq Signer
3. **Short description (≤132 chars):**
   ```
   Nostr identity in your browser: NIP-07 provider and NIP-46 signer. Keys stay local, encrypted at rest, no account.
   ```
4. **Detailed description:** wie `docs/store-listing.md`.
5. **Category:** Productivity (keine passendere Kategorie; „Developer Tools"
   wäre irreführend).
6. **Language:** English (Deutsch als zweite Sprache im Listing ergänzen).
7. **Screenshots:** die fünf 1280×800 aus `store/screenshots/`.
8. **Store icon:** 128×128 (`dist/icons/grunq-128.png`).
9. **Privacy practices:**
   - **Single purpose:**
     ```
     Provides a local Nostr identity to this browser and to paired NIP-46
     clients: it signs events and encrypts/decrypts messages with a key that
     never leaves the extension.
     ```
   - **Permission justification:**
     - `storage` – "Stores the identity key (optionally encrypted), site
       approvals, bunker sessions, settings, profile draft and the audit log."
     - `alarms` – "Keeps the relay subscription alive and enforces the
       auto-lock idle timeout."
     - Content scripts on `http/https` – "Wraps `window.nostr` for pages the
       user explicitly approves; no data is read from pages."
   - **Remote code:** No.
   - **Data usage:** keine Checkbox für Sammlung/Weitergabe an Dritte;
     „Your data is not sold", „not used for unrelated purposes",
     „not used to determine creditworthiness".
   - **Privacy policy URL:** https://grunq.com/grunq-signer/privacy.html
10. **Distribution:** Public; Sichtbarkeit alle Länder, keine
    eingeschränkten Regionen.

## Release Notes (beide Stores)

```
First public release: NIP-07 provider (window.nostr) and NIP-46 signer
(bunker), NIP-49 passphrase protection with auto-lock, multiple identities
with an encrypted backup file, public profile editor (including banner,
website, NIP-05/lightning checks, NIP-05 claim requests and live preview), QR identity export,
multi-device warning and an audit log. English/German UI follows the browser
language.
```

## Nach der Veröffentlichung

- [ ] Store-URLs in `docs/store-listing.md` und auf der Landing-Page
      (`deploy/landing/grunq-signer/index.html`, Buttons „Listing in
      preparation" → Store-Links) eintragen.
- [ ] Git-Tag `v1.0.0` (lokal gesetzt) und GitHub-Release mit dem ZIP.
- [ ] `README.md`: Badge/Link zum Store ergänzen.
- [ ] Erste Rückmeldungen aus den Stores in `SECURITY.md`/Issues kanalisieren.

## Bekannte Punkte vor dem Einreichen

- **Verschlüsselte Identität + Browser-Neustart:** Der Signer startet
  gesperrt und wartet auf das Entsperren im Popup. Das ist beabsichtigt
  (Schlüssel nur im RAM) und im README dokumentiert.
- **`web-ext lint`-Warnungen:** `background.service_worker` (Chromium-Pfad,
  von Firefox ignoriert) und `data_collection_permissions` (Android-Minimum);
  beides erwartbar, keine Fehler.
- **NIP-46-Live-Test** mit dem Grunq-Knoten vor dem Einreichen einmal
  durchklicken – Checkliste in `docs/store-listing.md`.
- **NIP-05-Claim** ist rein optional und braucht den Betreiber: Anfrage aus
  dem Profil-Editor → `contact@grunq.com` → `tools/nip05-claim.mjs`
  (Ablauf: `grunq/deploy/nip05/README.md`).
