#!/usr/bin/env node
'use strict';

/**
 * sphere — thin launcher.
 *
 * The actual CLI is a sealed, signed+notarized native binary (PyInstaller bundle
 * of the SPHERE engine). It is auto-placed in a roomy directory by the install
 * step (see scripts/engine.js). This launcher locates it, re-downloads it if it
 * has gone missing (e.g. scratch purge), optionally caches it on node-local disk
 * for fast startup on network filesystems, and forwards argv. No algorithm code
 * ships in the npm package.
 */

const { spawnSync } = require('child_process');
const engine = require('./engine.cjs');

const tell = (m) => process.stderr.write(`sphere: ${m}\n`);

let bin;
try {
  bin = engine.resolveBinary();
  if (!bin) {
    tell('engine not found — installing it now (one-time) …');
    bin = engine.ensureInstalled((m) => process.stderr.write(`  ${m}\n`));
  }
} catch (e) {
  tell(`could not locate or install the engine: ${e.message}`);
  tell('try:  npm install -g sphere-cli   (or set SPHERE_HOME=/path/with/space)');
  process.exit(1);
}

const run = engine.fastBinary(bin, tell);

const res = spawnSync(run, process.argv.slice(2), { stdio: 'inherit' });
if (res.error) {
  tell(`failed to launch: ${res.error.message}`);
  process.exit(1);
}
process.exit(res.status === null ? 1 : res.status);
