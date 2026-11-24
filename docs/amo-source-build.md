# Source code submission (AMO reviewers)

The extension is a bundled build: six ES-module entry points are bundled with
**esbuild** into the plain IIFE scripts that `manifest.json` references. The
source is complete and public; this document explains how to reproduce the
uploaded `dist/` folder one-to-one.

- Source: `https://github.com/Dstracke/grunq-signer` (also attached as a source
  ZIP built with `git archive`, so it contains no build output, no
  `node_modules`, no secrets)
- License: AGPL-3.0

## Toolchain

| Tool | Version used | Notes |
|---|---|---|
| Node.js | 22.23.1 (works on 20.x as well) | only for the build, not at runtime |
| npm | 10.9.8 | `npm ci` uses the committed `package-lock.json` |
| esbuild | 0.25.12 | pinned exact in `package-lock.json` (`devDependencies`) |
| `@noble/curves`, `@noble/hashes`, `@noble/ciphers` | 2.x | runtime crypto, bundled into `content/inpage.js`, `background/index.js`, `options/options.js` |

No post-install scripts are used, no other build tool, no template engine, no
CSS preprocessor. `npx web-ext` is only used to lint/package, never to build.

## Reproduce

```bash
unzip grunq_signer-1.0.1-source.zip -d grunq-signer
cd grunq-signer
npm ci            # installs esbuild + the three @noble packages from the lockfile
npm run build     # = node build.mjs  → writes dist/
npm test          # optional: 126 tests, no network needed (Relay-E2E is skipped)
npm run lint      # optional: web-ext lint (expects only BACKGROUND_SERVICE_WORKER_IGNORED)
```

`dist/` then contains exactly the files that are in the store artifact
(`web-ext-artifacts/grunq_signer-<version>.zip`), same paths, same contents.
Only ZIP timestamps differ between builds.

## What the build does

`build.mjs` has two steps and no code generation beyond bundling:

1. **esbuild** bundles these entry points, `format: iife`, `platform: browser`,
   `target: firefox128 + chrome111`, **`minify: false`**, `legalComments:
   inline`, no source maps:

   | Output | Entry point |
   |---|---|
   | `background/index.js` | `src/background/index.js` |
   | `content/inpage.js` | `src/content/inpage.js` |
   | `content/bridge.js` | `src/content/bridge.js` |
   | `popup/popup.js` | `src/popup/popup.js` |
   | `approval/approval.js` | `src/approval/approval.js` |
   | `options/options.js` | `src/options/options.js` |

   The output is readable, unminified JavaScript; every import is inlined from
   `src/lib`, `src/signer` or `node_modules/@noble/*`.

2. **Plain copies** (`cp`), byte-identical: `src/manifest.json`,
   `popup|approval|options/*.html|*.css`, `_locales/**`, `icons/**`,
   `fonts/*.woff2`.

Nothing is fetched at runtime; there is no remote code, no `eval`, no
`new Function`, no data URLs with scripts. The extension talks only to the
Nostr relays configured in its settings (default `wss://relay.grunq.com`).

## Where things live

| Area | Source |
|---|---|
| MV3 manifest, permissions (`storage`, `alarms`), gecko settings | `src/manifest.json` |
| Background (NIP-07/NIP-46 logic, storage, auto-lock, relay pool) | `src/background/index.js` |
| Page-side `window.nostr` wrapper + bridge | `src/content/inpage.js`, `src/content/bridge.js` |
| Crypto (NIP-04/NIP-44/NIP-49), keys, bech32, base64 | `src/lib/` |
| Signer core, keystore, sessions, profile, audit | `src/signer/` |
| UI (popup, approval window, options) | `src/popup/`, `src/approval/`, `src/options/` |
| Localisation (en default, de bundled) | `src/_locales/` |
| QR code (vendored, MIT) | `src/vendor/qrcode-generator.cjs` |

Questions about the build can go to `contact@grunq.com`.
