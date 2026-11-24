# Release 1.0.1 – AMO-Update

Update auf das bereits freigegebene 1.0.0
(<https://addons.mozilla.org/en-US/firefox/addon/grunq-signer/>). Alles, was
für die Einreichung bei **addons.mozilla.org** gebraucht wird; Chrome Web
Store bekommt dasselbe ZIP.

## Status

- **Build/Tests/Lint:** grün (Build `1.0.1`, 126 Tests, 1 übersprungener
  Relay-E2E, `web-ext lint`: 0 Fehler, 1 bekannte Warnung
  `BACKGROUND_SERVICE_WORKER_IGNORED`).
- **AMO:** vorbereitet am **24.11.2026**, Einreichung steht aus.
- **Add-on-ID:** `signer@grunq.com` (unverändert, Update ersetzt 1.0.0 für
  alle Nutzer nach der Freigabe).
- **Mindestversionen:** Firefox Desktop 140, Firefox Android 142,
  Chromium 111 (unverändert).

## Inhalt

- **Behoben:** „Von Relays laden“ ließ den Profil-Editor leer – der Abruf
  verwarf die geladenen Felder und lud anschließend den leeren lokalen
  Speicher neu. Jetzt landen die Felder im Editor und in der Vorschau, bis
  man sie mit „Profil veröffentlichen“ übernimmt.
- **Neu:** Identitäten lassen sich im Options-Page umbenennen (Inline-Feld,
  Enter speichert, Escape bricht ab). Die Bezeichnung ist lokale Metadaten
  (`identity.rename`), wird nie veröffentlicht und braucht keinen Unlock.
- **Doku/Changelog:** Mindestversionen aus dem 1.0.0-Store-Build sind im
  CHANGELOG nachgezogen; neuer Regressionstest `test/options.test.mjs`.

## Artefakt

```bash
npm ci
npm run build
npm test          # 126 Tests, Relay-E2E ohne Relay übersprungen
npm run lint      # 0 Fehler, 1 bekannte Warnung
npm run package   # -> web-ext-artifacts/grunq_signer-1.0.1.zip
git archive --format=zip -o web-ext-artifacts/grunq_signer-1.0.1-source.zip \
  v1.0.1 $(git ls-tree --name-only v1.0.1 | grep -v '^store$')
```

| Feld | Wert |
|---|---|
| Datei | `web-ext-artifacts/grunq_signer-1.0.1.zip` |
| Größe | 178.532 Bytes (~174 KB), 30 Dateien, `manifest.json` im ZIP-Root |
| SHA-256 | `37ef47a393820fb4da9491af5dad17653d628051d454717073e302f1adc90188` (lokaler Build; ZIP-Inhalte reproduzierbar, Byte-Hash je Build wegen Zeitstempeln verschieden) |
| Quelltext-ZIP | `grunq_signer-1.0.1-source.zip` (`git archive` vom Tag `v1.0.1`, ohne Build-Output, `node_modules` und Store-Screenshots; Dateien im ZIP-Root) |
| Add-on-ID | `signer@grunq.com` |
| Lizenz | AGPL-3.0 |
| Datenschutz | https://grunq.com/grunq-signer/privacy.html |
| Homepage | https://grunq.com/grunq-signer/ |
| Quellcode | https://github.com/Dstracke/grunq-signer |
| Support | contact@grunq.com |

**Reproduzierbarkeit geprüft (24.11.2026):** Quelltext-ZIP entpackt,
`npm ci && npm run build` erzeugt ein byte-identisches `dist/`; `npm test`
läuft daraus grün (125 pass, 1 Relay-E2E übersprungen).

## AMO-Ablauf (Update)

1. <https://addons.mozilla.org/developers/addons> → **Grunq Signer** →
   **„Neue Version hochladen“**.
2. `grunq_signer-1.0.1.zip` hochladen (die Version im Manifest ist `1.0.1`,
   also höher als die veröffentlichte `1.0.0`).
3. Auf die Frage nach dem Quelltext **„Ja“** und
   `grunq_signer-1.0.1-source.zip` anhängen; Reproduktion steht in
   [`amo-source-build.md`](amo-source-build.md) (`npm ci && npm run build`).
4. **Release Notes** (siehe unten) einfügen.
5. **Plattformen:** Firefox Desktop (Android weiterhin nicht beworben).
6. **Notes to reviewer:** unverändert wie bei 1.0.0 – kein Remote-Code, das
   Bundle ist unminifiziert (`dist/` im Quelltext-ZIP oder im Repo), Relays
   sind editierbar (Default `wss://relay.grunq.com`), keine Telemetrie.
7. **Data collection:** „This add-on collects no data“
   (`data_collection_permissions.required = ["none"]`).
8. Einreichen. Nach der Freigabe aktualisiert AMO alle Installationen
   automatisch; kein neues Listing, keine neuen Screenshots nötig.

## Release Notes (beide Stores)

EN (AMO „Release notes“):

```
Fixes "Load from relays" leaving the profile editor empty: fetched profile
fields now fill the editor (and preview) until you publish them. Adds inline
renaming for identities in the options page (Enter saves, Escape cancels) -
the label is local metadata and is never published.
```

DE (Listing-Sprache Deutsch):

```
Behebt, dass "Von Relays laden" den Profil-Editor leer ließ: Geladene
Profilfelder landen jetzt im Editor (und in der Vorschau), bis man sie
veröffentlicht. Neu: Identitäten lassen sich in den Einstellungen umbenennen
(Enter speichert, Escape bricht ab) - die Bezeichnung bleibt lokal und wird
nie veröffentlicht.
```

## Nach der Veröffentlichung

- [ ] AMO-Freigabe abwarten (Version erscheint dann als 1.0.1 im Listing).
- [ ] GitHub-Tag `v1.0.1` pushen und Release-Artefakt anhängen
      (`.github/workflows/release.yml` baut das ZIP am Tag).
- [ ] Chrome Web Store: gleiches ZIP einreichen, sobald das Listing steht.
`docs/store-listing.md` und `README.md` zeigen bereits auf 1.0.1.
