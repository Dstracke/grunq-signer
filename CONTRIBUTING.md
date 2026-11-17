# Contributing

Thanks for looking at Grunq Signer! This is a small, security-sensitive
extension — a few rules keep it reviewable.

## Before you open a PR

```bash
npm ci
npm run build     # bundles into dist/
npm test          # crypto, NIP-07/46, NIP-49, keystore, profile, i18n, ...
npm run lint      # web-ext lint on dist/
```

`npm test` includes an end-to-end block against a real relay. It is skipped
when no relay is reachable; to run it:

```bash
RELAY_WS=ws://localhost:7777 npm test
```

## Ground rules

- **Keys never leave the background.** Content scripts and pages only see
  signed results; no new code path may hand out key material (no exceptions,
  not even for "convenience").
- **Approvals stay explicit.** New operations that touch identity, signing or
  decryption need a confirmation dialog that shows the origin/client. If you
  add a cached "always allow", scope it narrowly (per origin, per kind).
- **No remote code, no telemetry, no accounts.** The only network traffic is
  to relays the user configured (and, for the on-demand profile checks, to the
  domain the user typed — https only, size/time limited).
- **Localization is a test.** Every UI string goes through `t()` /
  `data-i18n*`; `test/i18n.test.mjs` fails if a key is missing in a locale.
  English is the default/fallback.
- **Tests for behaviour, not for coverage.** New logic in `src/signer/` and
  `src/lib/` comes with a unit test using injected storage/transport/clock —
  no browser required.
- **Commit style:** short imperative subject. Keep unrelated changes separate.

## Reporting bugs

Open an issue with the browser and OS, the extension version (popup → footer
or `manifest.json`), and the exact steps. Security problems: see
[`SECURITY.md`](SECURITY.md) and e-mail instead of opening an issue.

## License

By contributing you agree that your changes are licensed under AGPL-3.0.
