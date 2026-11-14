# Grunq Signer

Browser-Extension als Identitätsquelle für Nostr: **NIP-07-Provider**
(`window.nostr` für freigegebene Seiten) **und NIP-46-Signer** (bunker) für
fremde Clients – damit wird der Desktop-Browser zur Signer-App: Der nsec
liegt im Extension-Storage und verlässt den Extension-Background nie.

Erstklassiges Ziel ist **Firefox/Gecko** (und damit der Zen-Browser),
Chromium läuft über denselben Codepfad. Standard-Connect-Relay ist das
Grunq-Bootstrap-Relay `wss://relay.grunq.com` (editierbar, keine
Cloud-Pflicht); das öffentliche Nutzerprofil (Kind 0) wird in der Extension
gepflegt und an die Allowlist-Relays veröffentlicht.

## Status

Spec-Phase: Die Spezifikation liegt unter
[`docs/browser-extension-spec.md`](docs/browser-extension-spec.md)
(Architektur, NIP-07-Schicht, NIP-46-Signer-Schicht, Security, Testplan,
Meilensteine M1–M4). Implementierung noch nicht begonnen.

## Verwandte Projekte

- **Grunq-Knoten** (dezentraler Live-Streaming-Client in Go, dieses Projekt
  ist seine Browser-Identitäts-Extension):
  `ssh://luku@192.168.0.99/home/luku/projekte/grunq.git`
- **Ideen-Repository** (Roadmap; die Extension-Idee ist GQ-37):
  `ssh://luku@192.168.0.99/home/luku/projekte/ideen.git`
  (`grunq/GQ-37-browser-signer-extension.md`)

## Lizenz

GNU Affero General Public License v3.0 (AGPL-3.0), siehe
[`LICENSE`](LICENSE) – wie der Grunq-Knoten.
