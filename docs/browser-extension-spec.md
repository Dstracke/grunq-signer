# Spec: Grunq Signer — Browser-Extension (NIP-07 + NIP-46)

Status: Entwurf (GQ-37) · 14.11.2026 · Repo: `grunq-signer`
(`ssh://luku@192.168.0.99/home/luku/projekte/grunq-signer.git`)

Schwesterprojekt des **Grunq-Knotens**
(`ssh://luku@192.168.0.99/home/luku/projekte/grunq.git`); Idee und
Hintergrund: GQ-37 im Ideen-Repo
(`ssh://luku@192.168.0.99/home/luku/projekte/ideen.git`).

## 1. Überblick

Eine Browser-Extension („Grunq Signer"), die den Browser zur Identitäts- und
Signierquelle macht:

- **NIP-07-Provider:** injiziert `window.nostr` auf freigegebenen Seiten
  (getPublicKey, signEvent, nip44-Encrypt/Decrypt) — Standard-Pfad für
  Nostr-Web-Apps im selben Browser.
- **NIP-46-Signer (bunker):** hält den User-Key im Extension-Storage und
  signiert für **fremde Clients** über Relays — Grunq-Knoten (Streamer-
  Identität via `bunker://`), Grunq-Viewer auf anderen Geräten
  (`nostrconnect://`), beliebige NIP-46-Clients.
- **Firefox-first:** erstklassiges Ziel ist Firefox/Gecko (und damit der
  Zen-Browser); Chromium folgt über denselben Codepfad. Test-Primärsystem
  ist Firefox.
- **Standard-Connect-Server:** das Grunq-Bootstrap-Relay
  `wss://relay.grunq.com` ist ab Werk Default-Relay für NIP-46-Pairing
  und Sessions sowie Veröffentlichungsort des öffentlichen Nutzerprofils
  (Kind 0) — editierbar und löschbar, keine Cloud-Pflicht (§8).

Damit ersetzt die Extension die „Signer-App auf dem Handy" durch den
Desktop-Browser: Streamer-Identität und Viewer-Chat-Identität können aus
einer Quelle kommen, ohne dass der nsec irgendeine App in Klartext sieht.

**Vorhandene Standards, keine Neuerfindung:** NIP-07, NIP-44, NIP-46,
NIP-49. Diese Spec definiert kein neues Protokoll — nur die Extension-
Architektur, die Berechtigungs- und Session-Politik und die
Grunq-Integration. (Der NIP-146-Ansatz „Signer als iframe" wurde 2025 vom
Autor als gescheitert geschlossen: instabiles Service-Worker-Verhalten,
partitionierte/ephemere Storage. Diese Spec meidet iframe/worker-Signing
bewusst und läuft alles über die Extension-Backgrounds.)

## 2. Begriffe

| Begriff | Bedeutung |
|---|---|
| **User-Key** | der nsec, den die Extension verwaltet (Genau ein aktiver Identity pro Profil in Stufe 1) |
| **NIP-07-Site** | eine Webseite, der per Site-Freigabe `window.nostr` zur Verfügung steht |
| **NIP-46-Client** | jedes Programm, das per Relays mit der Extension als Signer verbindet (Grunq-Knoten, Grunq-Viewer, Dritt-Apps) |
| **Session** | eine gekoppelte NIP-46-Verbindung: Client-Pubkey, Relays, erlaubte Methoden, Idle-Verhalten |
| **Pairing** | Aufbau einer Session: `bunker://` (Client kennt die URI) oder `nostrconnect://` (Client erzeugt URI, Extension bestätigt) |

## 3. Architektur

```
┌──────────────────────────── Browser ────────────────────────────┐
│                                                                  │
│  Content Script (isolated world)   ←→   Service Worker /        │
│  injiziert window.nostr Wrapper         Background-Skript        │
│         ↑ window.postMessage            - NIP-07-Logik           │
│  [Seite: grunq.example/watch]           - NIP-46-Relay-Pool      │
│                                         - Session-Registry       │
│  Popup / Options-Seite                  - Key-Storage            │
│  - Verbindungen koppeln/einsehen        - Bestätigungs-Queue     │
└──────────────────────────────────────────────────────────────────┘
```

- **Background (SW/Event-Page):** einzige Stelle mit Key-Zugriff; verwaltet
  Relay-Verbindungen (WebSocket), Sessions, Bestätigungs-Queue.
- **Content Scripts:** injizieren den NIP-07-Wrapper in freigegebene
  Seiten; sprechen mit dem Background über `window.postMessage` (isolated
  world → Background via `browser.runtime`).
- **Popup/Options-UI:** Pairing, Session-Liste, Freigaben, Key-Import/
  Export, Einstellungen (Relays, Auto-Lock).
- **Storage:** `browser.storage.local`; sensible Daten siehe §7.

Manifest: **MV3 für Chromium; Gecko (Firefox/Zen) als primäres Ziel** mit
MV3-Event-Pages (nicht Service Worker): `browser.*`-Namespace, WebSocket
in der Event-Page, `alarms` für Keepalive/Idle, `storage.local` für das
Datenmodell. Chromium nutzt denselben Codepfad hinter dem
Adapter-Layer `bg-runtime` (API-Unterschiede: SW-Lifecycle siehe §5.2,
`world: "MAIN"`-Injection ab Chromium 111 / Firefox 128).

## 4. NIP-07-Schicht

### 4.1 Injection

- Wrapper-Objekt mit den NIP-07-Methoden: `getPublicKey`, `signEvent`,
  `nip04.encrypt/decrypt`, `nip44.encrypt/decrypt`, `relays` (optional).
- Wrapper leitet Aufrufe als `window.postMessage({ source: "grunq-signer",
  id, method, params })` an das Content Script weiter; das Content Script
  ruft per Message den Background auf. Antworten laufen id-basiert zurück.
- **Site-Freigabe:** Beim ersten `window.nostr`-Zugriff einer unbekannten
  Seite öffnet der Background eine Bestätigung (Popup-Dialog): Domain
  sichtbar, „Zulassen" / „Immer zulassen" / „Ablehnen". Freigaben pro
  Origin in einer Allowlist; Revoke über das Popup.
- **Signier-Erinnerung pro Kind (umgesetzt):** `signEvent` zeigt standard-
  mäßig je Event einen Dialog — Chat-Schreiber (der Grunq-Viewer postet
  Kind 1311 pro Nachricht) würden sonst pro Nachricht ein Fenster
  öffnen. Der Dialog trägt deshalb **„Kind $K$ von $ORIGIN$ immer
  zulassen"**: Die Entscheidung legt `sign_kinds: [<kind>]` dauerhaft
  unter der Origin in `grunq_signer:permissions` ab; weitere Kind-Arten
  fragen weiter ab, Revoke über das Popup (Anzeige „Signieren ohne
  Nachfrage: Kind …"). Decrypt-Methoden bleiben je-Anfrage.
- **CSP-neutral:** kein Inline-Script; Wrapper wird über
  `world: "MAIN"`-registriertes Script gesetzt (Chromium ≥ 111, Firefox
  ≥ 128) bzw. Fallback per `<script src>`-Injection aus Extension-URL.

### 4.2 UX

- Jedes `signEvent` öffnet standardmäßig einen Bestätigungsdialog mit
  Domain, Event-Kind, `content`-Auszug und Ziel-Tags; optional pro Site
  „Kind 1311/1 ohne Nachfrage" (Whitelist nach Kind) — bewusst eng
  geschnitten, Default bleibt „immer nachfragen".
- Auto-Lock: nach `idle_minutes` (Standard 30, konfigurierbar) verlangt
  die Extension eine lokale Entsperrung (siehe §7), bevor signiert wird.
- **Identität exportieren / QR (umgesetzt):** Das Popup hat neben
  „npub kopieren" einen Knopf **„QR-Code / Export"**, der ein Panel mit
  zwei QRs öffnet (lokal erzeugt mit der gebündelten MIT-Bibliothek
  `qrcode-generator`, kein Netzzugriff — die Zeichenketten verlassen den
  Popup nie): **npub** öffentlich, sofort sichtbar; **nsec** erst nach
  einem zweiten, explizit bestätigten Schritt (Warnung + „Ja, nsec
  anzeigen"). Der Background liefert den nsec nur auf die Popup-Aktion
  `export` mit `confirm: true`, das Popup leert Text und QR beim
  Einklappen, Ausblenden und bei Identitätswechsel wieder. Damit lässt
  sich eine Identität per Scan in eine Signer-App aufs Handy übertragen
  (Migration statt Multi-Geräte-Sync; §12 bleibt offen).
- **Sprache:** Popup, Bestätigungsdialoge und Fehler folgen den
  Browsereinstellungen über die WebExtension-i18n-Mechanik (`_locales/`
  mit Deutsch + Englisch; Manifest-Texte via `__MSG_…__`,
  `default_locale: en`). Code-Kommentare und README sind englisch
  (Konvention: Englisch nach innen).

## 5. NIP-46-Signer-Schicht

### 5.1 Pairing

**`bunker://`-Pfad (Empfehlung für den Grunq-Knoten):**
- Extension erzeugt pro Client eine Einmal-Einladung:
  `bunker://<Signer-Pubkey>?relay=<r1>&relay=<r2>&secret=<one-time>`.
- Anzeige als Text + QR im Popup; der Grunq-Knoten fügt sie im Dashboard
  „Identität verbinden" ein (existierender Flow, GQ-03). Secret ist
  einmal gültig (NIP-46-Regel) und verfällt nach 10 min.

**`nostrconnect://`-Pfad (Client erzeugt die URI, z. B. Grunq-Viewer):**
- **Deep-Link ohne Copy-Paste (umgesetzt, b8b0815):** Die Grunq-Signer-
  Extension lauscht über ihr Content-Script auf `window.postMessage` der
  Seite: `{source:"grunq-signer-web", type:"ping"}` für die Erkennung
  (Antwort `{source:"grunq-signer", type:"pong"}`) und
  `{type:"nostrconnect", uri, replyId}` für die Kopplung. Das Background
  öffnet den Approval-Dialog (Client-Name, npub, Relays, **Origin der
  Seite**), bindet nach Freigabe die Session und sendet die Antwort an
  den Knoten; das Ergebnis geht als `{type:"nostrconnect-result",
  replyId, ok, npub|error}` an die Seite zurück. Grunq-Dashboard:
  Button „Mit Signer-Extension koppeln" (Grunq-Commit 391389e), Ping
  alle 15 s, QR bleibt als Fallback sichtbar, Auto-Confirm über den
  bestehenden Sitzungs-Poll. Nur ein Kopplungs-Approval gleichzeitig
  (Pages könnten den Dialog sonst fluten).
- **Handshake-Abweichung (Grunq-Knoten):** `pkg/nip46` erwartet im
  nostrconnect-Modus als erste Signer-Nachricht eine **Response-Form**
  `{id, result: <secret>, error: ""}` (`bridge.go handleResponse` prüft
  `resp.Result == s.secret`), nicht den Standard-`connect`-Request. Die
  Extension folgt der Knoten-Semantik (primärer Kopplungspartner).
- Popup-Feld „Koppeln" (URI einfügen, Clipboard-Button, optional
  `?nostrconnect=`-Parameter auf der Options-Seite) bleibt offen – der
  Dashboard-Deep-Link deckt den Hauptanwendungsfall ab.
- Nach dem Einfügen zeigt das Popup den Client-Namen, Client-Pubkey und
  die angefragten Relays; nach Bestätigung antwortet die Extension mit
  dem NIP-46-`connect`-Reply (NIP-44-verschlüsselt, `secret`-Match).

### 5.2 Relay-Handling und Session-Verhalten

- Pro Session eigener WebSocket-Pool auf den Session-Relays; Events:
  Client → Signer Kind **24133** (NIP-44-verschlüsselt an Signer-Pubkey),
  Antworten spiegelverkehrt. Filter auf `#p` = eigener Pubkey, `since`
  laufend.
- **Background-Lebenszyklus (der harte Teil, bewusst ein eigener
  Abschnitt):** Chromium-SW wird nach ~30 s Inaktivität beendet (Chromium
  ≥ 116 verlängert die Lebensdauer bei aktiver WebSocket-Aktivität);
  Firefox-Event-Pages terminieren ebenfalls. Strategie:
  1. Reconnect-on-wake: bei SW-Start Session-Registry laden und alle
     aktiven Sessions neu verbinden (Relays, Filter mit `since = now`).
  2. Keepalive: periodisches kurzes `ping`-Relay-Poll alle ≤ 25 s solange
     eine Session „aktiv" ist; Idle-Sessions (keine Client-Anfragen für
     `idle_minutes`, Standard 30) werden bewusst geschlossen.
  3. Benachrichtigungsoption: bei eingehender Anfrage in beendetem SW
     kann der Client einen Retry erwarten — Clients (und Grunq-Knoten,
     siehe ResilientStreamerSigner) kennen bereits Retry/Backoff; die
     Extension antwortet nach Reconnect erneut (NIP-46-Requests sind
     zustandslos id-basiert, Duplikate sind harmlos, Antworten werden
     per Request-Id dedupliziert).
- **Session-Registry (dauerhaft im Storage):** `client_pubkey`, Name,
  Relays, erstellt/am, zuletzt aktiv, erlaubte Methoden, Auto-Approve-
  Policy (Kinds-Whitelist oder „immer fragen").
- Limits orientieren sich an GQ-03: max. 16 Sessions, 10 min Bestätigungs-
  Fenster beim Pairing, 30 min Idle; nicht bestätigte Pairings verfallen.

### 5.3 Methoden (NIP-46)

Unterstützt: `connect`, `ping`, `get_public_key`, `get_relays`,
`sign_event`, `nip44_encrypt`, `nip44_decrypt`, `nip04_encrypt/decrypt`
(deprecated, pro Session abgeschaltbar). Kein `create_account`, keine
Delegation (NIP-26) in Stufe 1.

- `sign_event`: Standard „immer bestätigen" (Popup mit Event-Vorschau,
  Client-Name, Domain/Relay-Kontext); pro Session kann eine Kinds-
  Whitelist ohne Nachfrage freigegeben werden (z. B. Kind 1311 Chat).
  Auf `auth_url`-Flow verzichtet die Extension bewusst — Bestätigung
  läuft nativ im Popup, nicht als Web-Redirect (schließt den
  Phishing-Vektor, den NIP-146-Diskussion offenhielt).
  **Bunker-Perms erzwingen (umgesetzt, Popup-Flut-Fix):** Der
  `connect`-Request trägt einen NIP-46-Perms-String (`sign_event`,
  `sign_event:<kind>`, …); die Extension speichert ihn pro Session
  (`token.perms`) und **erzwingt** ihn jetzt in `sign_event`: Ein
  Client mit generischem `sign_event`-Perm (der Grunq-Knoten koppelt
  mit `sign_event,get_public_key,switch_relays`) signiert jede Kind-Art
  ohne Popup; `sign_event:1311` (Viewer-Kopplung) erlaubt nur Chat.
  Ohne Perm erscheint zusätzlich ein **„Kind $K$ immer zulassen"**-
  Button; die Entscheidung legt `sign_event:<kind>` dauerhaft in die
  Session-Perms. Hintergrund: Der Knoten signiert im Bunker-Betrieb
  laufend (Playlist-Spiegel alle 2 s, Ankündigung alle 20 min, Chat,
  Moderation) — ohne Perms/Erinnerung fluteten Approval-Fenster mit
  `grunq-playlist:`-Inhalten den Desktop (beobachtet gegen den echten
  Knoten, 15.11.2026). Das Decrypt-Gate bleibt bewusst je-Anfrage
  (§7), `saveSessions` läuft nach jeder Signatur.
- Antworten mit klaren Fehlercodes (`error:<code>:<id>`),
  z. B. `locked`, `unauthorized`, `unknown_method`.

## 6. Datenmodell (Storage)

```
grunq_signer:key           NIP-49-ncryptsec (siehe §7) oder Klartext
                           nsec in storage.local (Stufe 1, opt-in)
grunq_signer:identity      pubkey, name, erstellt
grunq_signer:permissions   { origin: { nip07: bool, kinds: [..] } }
grunq_signer:sessions      { client_pubkey: { name, relays, methods,
                             auto_approve_kinds, last_active, created } }
grunq_signer:pairings      offene Pairing-Invites { secret, relays,
                           expires, client_hint }
grunq_signer:settings      idle_minutes, relays (global allowlist),
                           confirm_defaults, lock
```

## 7. Security

- **Key at rest:** Stufe 1 Klartext-nsec im Extension-Storage ist Browser-
  Standard (wie NIP-07-Extensions); Empfehlung und Option: Import als
  NIP-49-`ncryptsec` + lokale Passphrase, Auto-Lock nach Idle. Export nur
  über expliziten Dialog mit Bestätigung — umgesetzt als QR-Panel mit
  zweistufiger nsec-Freigabe (§4.2); der nsec verlässt den Background nur
  auf diese eine, bestätigte Popup-Anfrage.
- **Kein Key-Transfer via Content-Script:** der nsec verlässt den
  Background nie; Seiten sehen ausschließlich signierte Ergebnisse.
- **Phishing:** NIP-07-Bestätigungen zeigen immer die volle Origin; im
  Popup keine fremden URLs anzeigen außer dem Bestätigungskontext.
  Kein `auth_url`-Popup (§5.3).
- **Pairing-Missbrauch:** nostrconnect-Secrets sind einmalig und kurz
  gültig; Sessions sind widerrufbar (Liste im Popup); unbekannte Clients
  erhalten nach Ablehnung kein Retry-Fenster (Rate-Limit auf Pairing-
  Versuche). **Secret-lose `bunker://`-Connects** (der Grunq-Knoten
  speichert nach nostrconnect-Pairing eine URI ohne Secret und
  reconnectet nach Neustart mit leerem Secret) erzeugen eine
  Bestätigungsfrage pro neuem Client-Key; der dafür vorgesehene
  Session-Slot wird bei erneuten Secret-los-Connects wiederverwendet
  (`provisional`-Flag), damit das Registry nicht mit toten Einträgen
  vollläuft. **Decrypt-Gate (umgesetzt):** `nip04_decrypt`/
  `nip44_decrypt` brauchen je Anfrage eine Bestätigung (Inhalt-Anfang
  wird angezeigt) – verhindert das Abfischen gestohlener Ciphertexte
  über eine gebundene Session.
- **Relays:** globale Allowlist; Session-Relays aus der nostrconnect-URI
  nur akzeptieren, wenn sie in der Allowlist stehen oder der Nutzer sie
  einzeln bestätigt. Kein Klartext-Telemetrie-Event.
- **Audit:** letzte 50 Anfragen pro Session im Popup einsehbar
  (Zeit, Methode, Client, Ergebnis).

## 8. Standard-Connect-Relay und Nutzerprofil (grunq.com)

- **Standard-Relay:** `wss://relay.grunq.com` (Grunq-Bootstrap-Relay,
  GQ-01) ist ab Werk in der globalen Relay-Allowlist und Default für
  NIP-46-Pairing-Einladungen (`bunker://`) und neue Sessions. Der Eintrag
  ist sichtbar, editierbar und löschbar — keine Cloud-Pflicht; ist das
  Grunq-Relay nicht erreichbar oder nicht gewünscht, läuft alles
  unverändert über die User-Relays.
  **Randbedingung (14.11.2026 verifiziert):** Ein Connect-Relay muss
  freie Writes erlauben — NIP-46-Clients signieren mit ephemeren Keys,
  Pubkey-Allowlists sind dort sinnlos. Fallstrick in nostr-rs-relay:
  `pubkey_whitelist` ist eine Option; vorhanden (auch leere Liste)
  blockiert ALLE Writes. Das Bootstrap-Relay läuft deshalb ohne
  Whitelist; Spamschutz über Rate-/Größen-Limits (5 msg/s, 64 KiB).
- **Nutzerprofil:** Die Extension pflegt das öffentliche Nostr-Profil
  (Kind 0: `name`, `display_name`, `about`, `picture`, `nip05`, `lud16`)
  in einem Profil-Editor und veröffentlicht es beim Speichern an die
  Allowlist-Relays — inklusive `relay.grunq.com`, damit die Identität
  dort dauerhaft auflösbar ist („Profil dort speichern"). Wie im
  Grunq-Knoten (GQ-09/GQ-26) folgt eine Nachveröffentlichung beim Start,
  falls das Profil dort fehlt.
- **Grenze (bewusst):** Gespeichert wird ausschließlich der öffentliche
  Kind-0-Event — nichts, was nicht ohnehin öffentlich wäre. Keine Keys,
  kein Chat, keine Kontakte, keine Telemetrie, kein Account; Löschen per
  NIP-09 auf das Profil-Event. Ein verschlüsselter Abgleich von
  Einstellungen/Sessions mit dem Grunq-Server wäre eine Cloud-Pflicht
  und ist bewusst Non-Goal (Grundsatz: keine zentralen Nutzerdatenbanken).
- **NIP-05 (offen):** GQ-01 sieht `name@grunq.com`-Adressen vor; wie eine
  Claim-Flow für Extension-Nutzer aussieht (ohne Account), bleibt
  offene Frage (§11).

## 9. Grunq-Integration

(Schwesterprojekt: Grunq-Knoten, `grunq.git` — die hier genannten Flows
laufen unverändert im Knoten, siehe auch GQ-03.)

1. **Streamer-Identität ohne Signer-App:** Extension zeigt `bunker://`-
   Einladung; Grunq-Dashboard „Identität verbinden" nimmt sie entgegen
   (existierender NIP-46-Pfad, inkl. Auto-Reconnect/Wartephase). Damit
   läuft die Identität im Desktop-Browser statt auf einem schlafenden
   Telefon — gleiche Garantien (npub bleibt in der Extension, Knoten
   sieht nur signierte Events).
2. **Viewer-Chat auf Geräten ohne Extension:** Grunq-Viewer zeigt
   `nostrconnect://`-URI/QR (existierender Flow); Nutzer kopiert die URI
   auf das Desktop-Gerät (Clipboard-Sync/Messenger) und koppelt dort die
   Extension. Badge „Gleiche Identität wie dieser Knoten" funktioniert
   unverändert.
3. **NIP-07 im selben Browser:** Viewer-/Dashboard-Seiten profitieren
   automatisch von der Injection — keine zusätzliche Konfiguration nötig;
   Grunq-Chat-Flow NIP-07 (Kind 1311 signiert lokal im Browser) bleibt
   der schnellste Pfad.

## 10. Testplan

- NIP-07: Test-Seite mit window.nostr-Aufrufen (getPublicKey, signEvent,
  nip44 roundtrip) gegen Content-Script-Injection; Berechtigungsdialog
  (erster Zugriff, Ablehnen, Revoke).
- NIP-46: Mini-Client (bereits vorhandenes Testmuster aus GQ-03) verbindet
  per bunker:// und nostrconnect://, signiert Kind 1311; SW-Kill-Test:
  Background beenden → Client-Retry → Antwort nach Reconnect.
- Auto-Lock, Session-Ablauf, 16-Session-Limit, Widerruf.
- Browser: **Firefox/Zen als Test-Primärsystem** (Event-Pages, Injection,
  WebSocket-Lebensdauer), Chromium als Zweitziel; unter Grunq-Windows
  nichts Besonderes (Extension läuft in den Browsern).
- Standard-Relay: Kopplung über `relay.grunq.com`; Fallback-Test mit
  gelöschtem/erreichbarem Grunq-Relay (alles läuft weiter über
  User-Relays).
- Profil: Kind-0-Veröffentlichung an Allowlist-Relays, Nachveröffentlichung
  beim Start, NIP-09-Löschung.

## 11. Meilensteine

- **M1 — NIP-07-Kern:** Key-Import, Injection, Bestätigungen, Allowlist.
- **M2 — NIP-46-Signer:** Relay-Pool, bunker://-Einladungen, Sessions,
  `sign_event` mit Bestätigung, Reconnect-on-wake.
- **M3 — Poliert:** nostrconnect-Kopplung inkl. Options-Seiten-Deep-Link,
  Kinds-Whitelist, Audit-Log, ncryptsec-Import, Auto-Lock, Profil-Editor
  (Kind 0) mit Veröffentlichung an die Allowlist-Relays.
- **M4 (optional):** Multi-Identity (Streamer-/Chat-Identität getrennt),
  NIP-26-Delegation, Web-NWC (`nostr+walletconnect`) als Client-Rolle.

## 12. Offene Fragen

- Gecko: stabilste Variante für dauerhafte Relay-Verbindungen (Event-Page
  + Alarms vs. offenes Popup mit eigenem WebSocket) — M2 entscheidet anhand
  von Messungen; Firefox ist Test-Primärsystem.
- Soll die Extension `window.nostr` per Default auf allen Sites oder nur
  nach Freigabe injizieren (Empfehlung hier: nur nach Freigabe)?
- NIP-05-Claim-Flow für `name@grunq.com` ohne Account (GQ-01): wie
  verifiziert die Extension eine NIP-05-Adresse, die auf dem Grunq-Server
  liegt, ohne einen zentralen Nutzer-Account einzuführen?
- Verhalten bei Multi-Gerät mit derselben Identität (Extension am Desktop,
  Signer-App am Handy): Konfliktauflösung in NIP-46 ist offiziell offen —
  Grunq-Knoten verbindet nur eine Session; doppelte Kopplung mit Hinweis
  blockieren.

## 13. Verbreitung und Nutzung durch Dritte

Die Extension ist bewusst **projektneutral nutzbar**: Sie definiert kein
eigenes Protokoll, sondern implementiert nur offene NIPs (07, 44, 46, 49).
Daraus ergibt sich die Verbreitung fast von selbst:

- **Beliebige Nostr-Web-Apps** erhalten `window.nostr` per NIP-07 (Login,
  Posten, Chat) — die Extension ist der Firefox-first-Provider (Alby ist
  Chromium-lastig; Zen/Firefox-Nutzer brauchen eine Alternative).
- **Mobile Signer-Apps und Clients** koppeln per `nostrconnect://` gegen den
  Desktop-Bunker; **andere Knoten-/Server-Software** nutzt `bunker://`-
  Einladungen — derselbe Weg wie der Grunq-Knoten (§9), ohne Grunq-Abhängigkeit.
- **Entwickler** entwickeln gegen die vollständige NIP-07-Oberfläche und die
  beigelegte Test-Seite (§10).

Voraussetzungen, damit Dritte sie wirklich einsetzen:

1. **Neutrale Defaults:** Erster Start fragt das Relay-Set ab
   (Grunq-Relay vorausgewählt, austauschbar); UX-Texte generisch („deine
   Signer-Extension"), Grunq-Branding dezent. Kein Feature darf Grunq-
   Server voraussetzen.
2. **Verteilung:** signiertes XPI auf Mozilla AMO (Firefox braucht
   Signaturen außer für temporäre Installation), Chrome Web Store,
   zusätzlich Release-XPI im Repo (Self-Distribution).
3. **Entwickler-Onboarding:** Test-Seite (window.nostr-Aufrufe,
   nip44-Roundtrip) und Kurzdoku als Teil des Repos.
4. **Kosten-Grenze:** Mehr Verbreitung erhöht den Traffic auf
   `relay.grunq.com`. Das Relay bleibt offen für alle (GQ-01), aber
   Kapazitäts-Envelopes (Connection-Limits, Rate-Limits) gehören in den
   Relay-Betrieb — sonst trägt der Grunq-Server das Wachstum fremder
   Ökosysteme. Erstinstallation weist darauf hin, dass das Grunq-Relay
   ein gemeinschaftlich betriebener Standard-Endpunkt ist.

Open-Core-Einordnung: Die Extension bleibt komplett AGPL-3.0 und gehört
zur offenen Client-Seite; keine proprietären Bestandteile (Zahlungs-Gateway,
gehostete Relays) fließen ein.

## 14. Non-Goals

- Keine Wallet-Funktionen (NWC senden), kein lightning-Zapping aus der
  Extension (GQ-27 lebt im Knoten/Browser).
- Kein iframe-basiertes Signer-Embedding (NIP-146-Totenzone).
- Keine eigene Relay-Infrastruktur, keine Telemetrie, kein Account.
- Kein Cloud-Abgleich von Einstellungen, Sessions oder Keys mit dem
  Grunq-Server — dort gespeichert wird ausschließlich das öffentliche
  Kind-0-Profil.
