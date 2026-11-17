// Localization guard: the extension follows the browser language (WebExtension
// i18n) with English as the default/fallback locale. These tests keep the
// catalogs honest: same keys everywhere, valid placeholders, and every UI
// string actually used by the pages/scripts exists in every locale.
import assert from 'node:assert/strict';
import test from 'node:test';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';

const SRC = new URL('../src/', import.meta.url).pathname;

function loadJson(path) {
  return JSON.parse(readFileSync(path, 'utf8'));
}

function walk(dir, out = []) {
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) walk(full, out);
    else if (/\.(js|html)$/.test(entry)) out.push(full);
  }
  return out;
}

const manifest = loadJson(join(SRC, 'manifest.json'));
const localeDirs = readdirSync(join(SRC, '_locales')).sort();
const catalogs = Object.fromEntries(
  localeDirs.map((code) => [code, loadJson(join(SRC, '_locales', code, 'messages.json'))]),
);

test('i18n: the default locale exists and is the English fallback', () => {
  assert.equal(manifest.default_locale, 'en');
  assert.ok(localeDirs.includes(manifest.default_locale));
  assert.ok(localeDirs.length >= 2, 'more than one locale is available');
});

test('i18n: every locale has the same keys and non-empty messages', () => {
  const reference = Object.keys(catalogs.en).sort();
  for (const code of localeDirs) {
    const keys = Object.keys(catalogs[code]).sort();
    assert.deepEqual(keys, reference, `locale ${code} key set differs from en`);
    for (const key of keys) {
      const msg = catalogs[code][key]?.message;
      assert.equal(typeof msg, 'string', `${code}/${key} has no message`);
      assert.ok(msg.trim().length > 0, `${code}/${key} is empty`);
    }
  }
});

test('i18n: placeholders are declared and referenced consistently', () => {
  for (const code of localeDirs) {
    for (const [key, entry] of Object.entries(catalogs[code])) {
      const used = [...String(entry.message).matchAll(/\$([A-Za-z0-9_]+)\$/g)]
        .map((m) => m[1].toLowerCase());
      const declared = Object.keys(entry.placeholders ?? {}).map((p) => p.toLowerCase());
      // Placeholder names are case-insensitive: the message writes $NPUB$ while
      // the "placeholders" key is "npub" (MDN/Chrome behaviour).
      for (const name of used) {
        assert.ok(declared.includes(name), `${code}/${key}: undeclared placeholder ${name}`);
      }
      for (const name of declared) {
        assert.ok(used.includes(name), `${code}/${key}: unused placeholder ${name}`);
      }
      for (const [name, def] of Object.entries(entry.placeholders ?? {})) {
        assert.match(String(def?.content ?? ''), /^\$\d+$/, `${code}/${key}: placeholder ${name} needs a $n content`);
      }
    }
  }
});

test('i18n: every UI string used by the extension exists in every locale', () => {
  const used = new Set();
  for (const file of walk(SRC)) {
    const text = readFileSync(file, 'utf8');
    for (const m of text.matchAll(/data-i18n(?:-placeholder|-alt|-aria-label|-title)?="([^"]+)"/g)) {
      used.add(m[1]);
    }
    for (const m of text.matchAll(/\bt\(\s*'([A-Za-z0-9_]+)'/g)) {
      used.add(m[1]);
    }
    // Error maps pass the key indirectly (`t(map[code])`); their literals all
    // start with "error" or "nip46Error" by convention.
    for (const m of text.matchAll(/'((?:error|nip46Error)[A-Za-z0-9]+)'/g)) {
      used.add(m[1]);
    }
  }
  assert.ok(used.size > 100, `found ${used.size} keys`);
  for (const code of localeDirs) {
    const missing = [...used].filter((key) => !(key in catalogs[code])).sort();
    assert.deepEqual(missing, [], `locale ${code} is missing UI keys`);
  }
});

test('i18n: manifest strings are localized', () => {
  const manifestKeys = [];
  for (const field of ['name', 'description']) {
    for (const m of String(manifest[field] ?? '').matchAll(/__MSG_([A-Za-z0-9_]+)__/g)) {
      manifestKeys.push(m[1]);
    }
  }
  assert.ok(manifestKeys.includes('extName'));
  assert.ok(manifestKeys.includes('extDescription'));
  for (const code of localeDirs) {
    for (const key of manifestKeys) {
      assert.ok(catalogs[code][key], `${code} misses manifest message ${key}`);
    }
  }
});
