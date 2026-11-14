// Bundles the extension into dist/ (IIFE, no modules - works on Gecko event
// pages and Chromium service workers alike) and copies static assets.
import { build } from 'esbuild';
import { cp, mkdir, readdir, stat } from 'node:fs/promises';
import { join } from 'node:path';

const OUT = 'dist';

await build({
  entryPoints: [
    'src/background/index.js',
    'src/content/inpage.js',
    'src/content/bridge.js',
    'src/popup/popup.js',
    'src/approval/approval.js',
  ],
  outdir: OUT,
  bundle: true,
  format: 'iife',
  platform: 'browser',
  target: ['firefox128', 'chrome111'],
  minify: false,
  legalComments: 'inline',
  logLevel: 'info',
});

async function copyTree(src, dest, extensions) {
  await mkdir(dest, { recursive: true });
  for (const entry of await readdir(src, { withFileTypes: true })) {
    const s = join(src, entry.name);
    const d = join(dest, entry.name);
    if ((await stat(s)).isDirectory()) await copyTree(s, d, extensions);
    else if (extensions.includes(entry.name.split('.').pop())) await cp(s, d);
  }
}

// manifest + html/css/_locales plus icons and the bundled font into the same
// relative paths the bundles live in (esbuild output is not overwritten
// because only html/css/png/woff2/json are copied)
await cp('src/manifest.json', join(OUT, 'manifest.json'));
for (const dir of ['popup', 'approval']) {
  await copyTree(join('src', dir), join(OUT, dir), ['html', 'css']);
}
await copyTree(join('src', '_locales'), join(OUT, '_locales'), ['json']);
await copyTree(join('src', 'icons'), join(OUT, 'icons'), ['png']);
await copyTree(join('src', 'fonts'), join(OUT, 'fonts'), ['woff2']);
console.log('dist/ ready');
