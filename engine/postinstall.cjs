'use strict';

/**
 * SPHERE CLI postinstall.
 *
 * Places the platform-specific sealed binary in a roomy, auto-detected location
 * (NOT inside node_modules — that would force users to repoint `npm config set
 * prefix` to dodge home-dir quotas). All the location/download/verify logic lives
 * in ./engine.js, shared with the launcher. This script just drives it, warms the
 * binary once, and wires up PATH so `sphere` is callable without manual setup.
 *
 * Env: SPHERE_SKIP_POSTINSTALL=1, SPHERE_HOME=<dir>, SPHERE_NO_PATH_SETUP=1.
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');
const engine = require('./engine.cjs');

const PKG_ROOT = path.join(__dirname, '..');
const PLATFORM = engine.PLATFORM;
function log(m) { process.stdout.write(`sphere-cli: ${m}\n`); }

if (process.env.SPHERE_SKIP_POSTINSTALL === '1') {
  log('SPHERE_SKIP_POSTINSTALL=1 — skipping binary download.');
  process.exit(0);
}
if (!engine.SUPPORTED.has(engine.KEY)) {
  process.stderr.write(
    `sphere-cli: no prebuilt binary for ${engine.KEY} ` +
    `(supported: ${[...engine.SUPPORTED].join(', ')}).\n`,
  );
  process.exit(0);
}

try {
  const bin = engine.ensureInstalled(log);
  log(`engine ready at ${bin}`);

  // Warm once (best-effort): the first run loads ~330 bundled libraries; doing it
  // now (while an install wait is expected) means the user's first real command
  // is fast. On macOS this also clears the one-time Gatekeeper scan.
  try {
    log('warming (first run loads the analysis stack; one-time) …');
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'sphere-warm-'));
    const warmIn = path.join(tmp, 'in.csv');
    const warmOut = path.join(tmp, 'out.csv');
    fs.writeFileSync(warmIn, 'a,b\n1.0,2.0\n3.0,4.0\n5.0,6.0\n');
    execFileSync(bin, ['generate', warmIn, '-o', warmOut], {
      stdio: 'ignore',
      timeout: 240000,
      env: { ...process.env, SPHERE_LICENSE_REQUIRED: 'false' },
    });
    fs.rmSync(tmp, { recursive: true, force: true });
    log('warmed ✓ — first run will be fast.');
  } catch (_) { /* best-effort */ }

  setupGlobalPath();
  log(`installed sealed binary for ${engine.KEY} ✓`);
} catch (e) {
  process.stderr.write(
    `sphere-cli: failed to install binary: ${e.message}\n` +
    `Retry: npm rebuild sphere-cli   (or set SPHERE_HOME=/path/with/space and retry)\n`,
  );
  process.exit(1);
}

// ── Make `sphere` callable without manual PATH editing ──────────────────────
// For a GLOBAL install whose prefix/bin is not already on PATH (common on HPC),
// append the bin dir to the user's shell rc. Because the rc lives in the shared
// home dir, the `sphere` command then works in every future session on every
// node. Idempotent; skipped when already on PATH; opt out with SPHERE_NO_PATH_SETUP=1.
function setupGlobalPath() {
  try {
    if (process.env.SPHERE_NO_PATH_SETUP === '1') return;
    if (PLATFORM === 'win32') return;
    const isGlobal = process.env.npm_config_global === 'true'
      || /[\\/]lib[\\/]node_modules[\\/]sphere-cli$/.test(PKG_ROOT);
    if (!isGlobal) return; // local installs run via `npx sphere` — no PATH needed

    const prefix = process.env.npm_config_prefix
      || path.resolve(PKG_ROOT, '..', '..', '..'); // <prefix>/lib/node_modules/sphere-cli
    const binDir = path.join(prefix, 'bin');
    const parts = (process.env.PATH || '').split(path.delimiter);
    if (parts.includes(binDir)) return; // already callable — nothing to do

    const home = os.homedir();
    const block = `\n# added by sphere-cli — makes the \`sphere\` command available\n`
      + `export PATH="${binDir}:$PATH"\n`;

    const targets = [];
    for (const f of ['.bashrc', '.zshrc']) {
      const p = path.join(home, f);
      if (fs.existsSync(p)) targets.push(p);
    }
    if (targets.length === 0) targets.push(path.join(home, '.bashrc')); // create one

    const wrote = [];
    for (const rc of targets) {
      let cur = '';
      try { cur = fs.readFileSync(rc, 'utf8'); } catch (_) {}
      if (cur.includes(binDir)) continue; // idempotent
      try { fs.appendFileSync(rc, block); wrote.push(path.basename(rc)); } catch (_) {}
    }

    if (wrote.length) {
      log(`PATH: added ${binDir} to ${wrote.join(', ')} — \`sphere\` works in new shells (and every node, since home is shared).`);
      log(`for THIS shell now:  export PATH="${binDir}:$PATH"`);
    } else {
      log(`to run \`sphere\`, add to your shell rc:  export PATH="${binDir}:$PATH"`);
    }
  } catch (_) { /* never fail the install over PATH setup */ }
}
