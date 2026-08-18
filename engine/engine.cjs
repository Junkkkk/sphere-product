'use strict';

/**
 * Shared engine logic for the SPHERE CLI npm package — used by BOTH the
 * postinstall (to place the binary) and the launcher (to find / self-heal /
 * fast-start it). No algorithm code lives here; this only locates, downloads,
 * verifies, and runs the sealed native binary.
 *
 * Design goals (works on ANY HPC / laptop, zero per-cluster config):
 *   1. The ~500 MB binary is NOT kept inside node_modules (that forces users to
 *      repoint `npm config set prefix` to dodge home-dir quotas). Instead it is
 *      placed in an auto-detected roomy directory — a generic scan of common HPC
 *      scratch/project vars, falling back to the XDG data dir.
 *   2. The launcher self-heals: if the binary is gone (scratch purged, moved),
 *      it re-downloads on next run.
 *   3. Fast-start: if the binary lives on a *network* filesystem (Lustre/NFS/
 *      GPFS — slow to open the ~330 bundled libs), cache a copy on node-local
 *      disk so startup isn't dominated by network round-trips.
 *
 * Env overrides: SPHERE_HOME (install dir), SPHERE_NO_FAST=1, SPHERE_FAST_DIR,
 *                SPHERE_NO_PATH_SETUP=1, SPHERE_BINARY_BASEURL, SPHERE_SKIP_POSTINSTALL.
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { execFileSync } = require('child_process');

const REPO = 'statzihuai/sphere-cli';
// Binary release tag — decoupled from the npm package version so JS-only patch
// releases reuse the same prebuilt/notarized binaries.
const BINARY_RELEASE = 'v0.2.9';

const PLATFORM = process.platform; // 'darwin' | 'linux'
const ARCH = process.arch;         // 'arm64' | 'x64'
const KEY = `${PLATFORM}-${ARCH}`;
const SUPPORTED = new Set(['darwin-arm64', 'darwin-x64', 'linux-x64']);
const ASSET = `sphere-${KEY}.tar.gz`;
const BASE = process.env.SPHERE_BINARY_BASEURL
  || `https://github.com/${REPO}/releases/download/${BINARY_RELEASE}`;

// ── small persistent record of where the binary was installed ────────────────
// Lives in the (tiny, always-writable) XDG config dir so the launcher can find
// the binary regardless of which roomy dir the installer chose.
function configFile() {
  const base = process.env.XDG_CONFIG_HOME || path.join(os.homedir(), '.config');
  return path.join(base, 'sphere-cli', 'install.json');
}
function readRecord() {
  try { return JSON.parse(fs.readFileSync(configFile(), 'utf8')); } catch (_) { return null; }
}
function writeRecord(rec) {
  try {
    fs.mkdirSync(path.dirname(configFile()), { recursive: true });
    fs.writeFileSync(configFile(), JSON.stringify(rec, null, 2));
  } catch (_) { /* best-effort */ }
}

// ── free space (GB) on the filesystem holding `dir` (best-effort) ────────────
function freeGB(dir) {
  try {
    let p = dir;
    while (p && !fs.existsSync(p)) p = path.dirname(p);
    if (!p) return Infinity; // unknown → don't exclude
    if (typeof fs.statfsSync === 'function') {
      const s = fs.statfsSync(p);
      return (s.bavail * s.bsize) / 1e9;
    }
  } catch (_) {}
  return Infinity; // can't tell → optimistic; real test is the extraction
}

// ── filesystem type magic (Linux statfs) → is this a slow network FS? ────────
const NETWORK_FS = new Set([
  0x6969,       // NFS
  0xff534d42,   // CIFS/SMB
  0x0bd00bd0,   // Lustre
  0x47504653,   // GPFS
  0x19830326,   // BeeGFS/FhGFS
  0x65735546,   // FUSE (often network-backed: sshfs, etc.)
  0x1161970,    // CODA
]);
function isNetworkFS(dir) {
  try {
    if (typeof fs.statfsSync !== 'function') return false;
    let p = dir;
    while (p && !fs.existsSync(p)) p = path.dirname(p);
    const t = fs.statfsSync(p).type;
    return NETWORK_FS.has(t);
  } catch (_) { return false; }
}

// ── ordered list of dirs to try installing into (roomy, persistent-preferred) ─
function candidateDirs() {
  const sub = path.join('sphere-cli', BINARY_RELEASE);
  if (process.env.SPHERE_HOME) return [path.join(process.env.SPHERE_HOME, BINARY_RELEASE)];

  const home = os.homedir();
  const env = process.env;
  const looksHpc = !!(env.SCRATCH || env.WORK || env.PROJECT || env.OAK
    || env.GROUP_HOME || env.PI_HOME || env.SLURM_JOB_ID || env.PBS_JOBID
    || env.LSB_JOBID || env.GROUP_SCRATCH || env.PSCRATCH);

  const persistent = ['WORK', 'PROJECT', 'PROJECTS', 'OAK', 'GROUP_HOME', 'PI_HOME', 'DATA']
    .map((v) => env[v]).filter(Boolean);
  const scratch = ['SCRATCH', 'PSCRATCH', 'GROUP_SCRATCH']
    .map((v) => env[v]).filter(Boolean);

  const xdg = env.XDG_DATA_HOME
    ? path.join(env.XDG_DATA_HOME, 'sphere-cli', BINARY_RELEASE)
    : path.join(home, '.local', 'share', sub);

  // On a cluster: prefer roomy persistent storage, then scratch; always keep the
  // XDG home dir as a last resort. On a laptop: just the XDG dir.
  let candidates = looksHpc
    ? [...persistent, ...scratch].map((d) => path.join(d, '.' + sub)).concat([xdg])
    : [xdg];

  // Stable de-dup, then float the ones that *look* like they have space to the
  // front (df can't see per-user quotas, so this is a hint — installInto() falls
  // through to the next candidate if extraction actually runs out of space).
  candidates = [...new Set(candidates)];
  const withSpace = candidates.filter((c) => freeGB(path.dirname(path.dirname(c))) >= 1.5);
  const without = candidates.filter((c) => !withSpace.includes(c));
  return [...withSpace, ...without];
}

// Ensure the binary is installed; returns its path. Idempotent — if a matching
// install is already recorded and present, returns it without re-downloading.
// Tries each candidate dir until one works (handles quota/space failures).
function ensureInstalled(log) {
  log = log || (() => {});
  const existing = resolveBinary();
  if (existing) return existing;
  let lastErr;
  for (const dir of candidateDirs()) {
    try {
      const bin = installInto(dir, log);
      writeRecord({ release: BINARY_RELEASE, key: KEY, dir, bin });
      return bin;
    } catch (e) {
      lastErr = e;
      try { fs.rmSync(path.join(dir, 'sphere-cli'), { recursive: true, force: true }); } catch (_) {}
    }
  }
  throw lastErr || new Error('no writable install location with enough space found');
}

// ── download + checksum + extract into <dir>/sphere-cli ──────────────────────
function curl(url, dest) {
  execFileSync('curl', ['-fL', '--retry', '3', '--retry-delay', '2',
    '--connect-timeout', '30', '-o', dest, url], { stdio: ['ignore', 'ignore', 'inherit'] });
}
function sha256(file) {
  const h = crypto.createHash('sha256');
  h.update(fs.readFileSync(file));
  return h.digest('hex');
}

// Download the platform tarball into `dir`, verify SHA256, extract so that
// `dir/sphere-cli/sphere` exists. Returns the binary path. Throws on failure.
function installInto(dir, log) {
  log = log || (() => {});
  fs.mkdirSync(dir, { recursive: true });
  const tarball = path.join(dir, ASSET);

  log(`downloading ${ASSET} (${BINARY_RELEASE}) …`);
  curl(`${BASE}/${ASSET}`, tarball);

  const sumsFile = path.join(dir, 'SHA256SUMS.txt');
  curl(`${BASE}/SHA256SUMS.txt`, sumsFile);
  const expected = fs.readFileSync(sumsFile, 'utf8').split('\n')
    .map((l) => l.trim().split(/\s+/))
    .find((p) => p[1] && p[1].endsWith(ASSET));
  if (!expected) throw new Error(`no checksum for ${ASSET}`);
  const got = sha256(tarball);
  if (got !== expected[0]) throw new Error(`checksum mismatch for ${ASSET}`);
  log('checksum verified ✓');

  fs.rmSync(path.join(dir, 'sphere-cli'), { recursive: true, force: true });
  execFileSync('tar', ['-xzf', tarball, '-C', dir], { stdio: 'inherit' });
  fs.rmSync(tarball, { force: true });
  fs.rmSync(sumsFile, { force: true });

  const bin = path.join(dir, 'sphere-cli', 'sphere');
  if (!fs.existsSync(bin)) throw new Error('extraction did not produce sphere binary');
  fs.chmodSync(bin, 0o755);
  if (PLATFORM === 'darwin') {
    try { execFileSync('xattr', ['-cr', path.join(dir, 'sphere-cli')], { stdio: 'ignore' }); } catch (_) {}
  }
  return bin;
}

// ── find the installed binary (record → that dir; else legacy vendor) ────────
function vendorBin() {
  return path.join(__dirname, '..', 'vendor', 'sphere-cli', 'sphere');
}
function resolveBinary() {
  const rec = readRecord();
  if (rec && rec.release === BINARY_RELEASE && rec.bin && fs.existsSync(rec.bin)) return rec.bin;
  const v = vendorBin();
  if (fs.existsSync(v)) return v;
  return null; // caller decides to (re)install
}

// ── fast-start: if `bin` is on a network FS, run from a node-local copy ───────
// Network filesystems (Lustre/NFS/GPFS) are slow to open the ~330 bundled libs.
// Caching to local disk makes startup fast for the rest of the job. Only kicks
// in on network FS (local installs gain nothing); opt out with SPHERE_NO_FAST=1.
function fastBinary(bin, log) {
  log = log || (() => {});
  try {
    if (process.env.SPHERE_NO_FAST === '1') return bin;
    const srcDir = path.dirname(bin); // …/sphere-cli
    if (!isNetworkFS(srcDir)) return bin; // already local → nothing to gain
    const localRoot = process.env.SPHERE_FAST_DIR
      || process.env.L_SCRATCH || process.env.TMPDIR || os.tmpdir();
    if (!localRoot) return bin;
    const dest = path.join(localRoot, 'sphere-cli-cache', BINARY_RELEASE);
    const localBin = path.join(dest, 'sphere-cli', 'sphere');
    if (fs.existsSync(localBin)) return localBin; // already cached on this node
    if (freeGB(localRoot) < 1.5) return bin;       // not enough local space
    // copy once (first run on this node pays it; later runs in the job are fast).
    // Copy to a temp dir then rename so a partial/aborted copy is never used.
    log('caching engine to node-local disk for faster startup (one-time) …');
    fs.mkdirSync(path.dirname(dest), { recursive: true });
    const tmp = fs.mkdtempSync(path.join(localRoot, 'sphere-cache-'));
    execFileSync('cp', ['-a', srcDir, path.join(tmp, 'sphere-cli')], { stdio: 'ignore' });
    fs.rmSync(dest, { recursive: true, force: true });
    fs.mkdirSync(dest, { recursive: true });
    fs.renameSync(path.join(tmp, 'sphere-cli'), path.join(dest, 'sphere-cli'));
    fs.rmSync(tmp, { recursive: true, force: true });
    return fs.existsSync(localBin) ? localBin : bin;
  } catch (_) { return bin; } // any trouble → just use the original
}

module.exports = {
  KEY, ASSET, BINARY_RELEASE, SUPPORTED, PLATFORM,
  configFile, readRecord, writeRecord,
  candidateDirs, installInto, ensureInstalled, resolveBinary, fastBinary, vendorBin,
};
