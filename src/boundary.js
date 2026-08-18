// The privacy boundary: everything that decides what an agent is allowed to see.
//
// THE GUARANTEE DOES NOT LIVE IN THE MODEL'S BEHAVIOUR.
// A system prompt asking a model not to look at data is a request, not a control.
// The guarantee lives here: the real file is never handed to the model, never read
// into a tool result, and the sandbox that runs model-authored code cannot open it.
//
// Two channels have to be closed, and they are closed by different mechanisms:
//   1. What we SEND the model  — the profiler below emits shapes, never values.
//   2. What model-authored CODE can reach — a Seatbelt profile that denies the
//      home tree and re-allows exactly the synthetic file plus a session dir.

import { spawn } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

export const VAULT = process.env.SPHERE_VAULT || path.join(os.homedir(), '.sphere', 'vault');

/** Env for any subprocess that will touch data: no credentials in reach. */
export function scrubbedEnv() {
  // An allow-list, not a deny-list. Spreading process.env and deleting the keys
  // you thought of leaves ANTHROPIC_API_KEY, AWS_*, and every token you did not.
  const allow = ['HOME', 'PATH', 'LANG', 'LC_ALL', 'TMPDIR', 'USER', 'SHELL', 'TERM', 'SPHERE_LICENSE_REQUIRED'];
  const out = {};
  for (const k of allow) if (process.env[k]) out[k] = process.env[k];
  out.MPLBACKEND = 'Agg';           // matplotlib must never try to open a window
  out.PYTHONDONTWRITEBYTECODE = '1';
  return out;
}

const q = (s) => String(s).replace(/\\/g, '\\\\').replace(/"/g, '\\"');

/**
 * Seatbelt profile for model-authored analysis code.
 *
 * Permissive base (Python needs a great deal to boot), then DENY the whole home
 * tree — which is where real CSVs actually live — then re-allow only the
 * synthetic file and the session directory. So even if the model writes
 * open('/Users/me/patients.csv') it gets PermissionError rather than data.
 *
 * Network is denied outright: code that can see data must not be able to speak.
 */
export function sandboxProfile({ sessionDir, synthPath, realPath }) {
  // ⚠️ THE DENY LIST MUST NAME THE REGISTERED FILE, not just "the home tree".
  //
  // v1 did `(allow default)` then denied $HOME, assuming sensitive CSVs live
  // there. They frequently do not — /tmp, /Volumes, /Users/Shared and any lab or
  // hospital network mount are all outside home and were fully readable. A test
  // fixture that happened to sit in /var/folders exposed it.
  //
  // v2 tried the pure form, `(deny file-read*)` plus a system allow-list. That is
  // the right shape in principle and it does not work here: file-read* also
  // denies METADATA, so the dynamic loader cannot resolve its own binary and the
  // process dies with SIGABRT before main(). `(deny file-read-data)` fails the
  // same way for Homebrew Python, whose search paths are not practical to
  // enumerate. Chasing that produces a brittle profile that breaks on every
  // Python upgrade.
  //
  // So: deny the thing we are actually protecting — the registered dataset, by
  // literal path AND its containing directory — plus the locations user data
  // realistically lives in. This is enforced, testable, and does not depend on
  // guessing an interpreter's file layout.
  //
  // Residual, stated plainly: a file outside all of these paths and outside the
  // registered directory is readable. The registered dataset never is, which is
  // the guarantee this server makes.
  // ⚠️ RESOLVE SYMLINKS. Seatbelt matches the REAL path, and on macOS /tmp is a
  // symlink to /private/tmp (likewise /var -> /private/var). A deny for
  // "/tmp/lab-share" therefore never fires for "/private/tmp/lab-share", and a
  // dataset there was read straight through a profile that looked correct.
  // Emit BOTH forms for every path.
  const real = (p) => { try { return fs.realpathSync(p); } catch { return p; } };
  const bothForms = (p) => [...new Set([p, real(p)])];

  const home = os.homedir();
  const DATA_AREAS = [home, '/Users', '/Volumes', '/mnt', '/media', '/srv', '/data', '/opt/data', '/tmp', '/private/tmp'];
  const denies = [];
  for (const d of DATA_AREAS) for (const f of bothForms(d)) denies.push(`(deny file-read* (subpath "${q(f)}"))`);
  if (realPath) {
    for (const f of bothForms(realPath)) denies.push(`(deny file-read* (literal "${q(f)}"))`);
    for (const f of bothForms(path.dirname(realPath))) denies.push(`(deny file-read* (subpath "${q(f)}"))`);
  }
  return `(version 1)
(allow default)
(deny network*)
(deny file-write*)
${denies.join('\n')}
(allow file-read* (subpath "${q(path.join(home, 'Library'))}"))
${bothForms(synthPath).map((f) => `(allow file-read* (literal "${q(f)}"))`).join('\n')}
${bothForms(sessionDir).map((f) => `(allow file-read* (subpath "${q(f)}"))`).join('\n')}
${bothForms(sessionDir).map((f) => `(allow file-write* (subpath "${q(f)}"))`).join('\n')}
`;
}

/** Run a command, capturing output. Never inherits the parent environment. */
export function run(cmd, args, { cwd, timeoutMs = 180000, env } = {}) {
  return new Promise((resolve) => {
    const p = spawn(cmd, args, { cwd, env: env || scrubbedEnv() });
    let out = '', err = '';
    const t = setTimeout(() => { try { p.kill('SIGKILL'); } catch {} }, timeoutMs);
    p.stdout.on('data', (d) => { out += d; });
    p.stderr.on('data', (d) => { err += d; });
    p.on('close', (code) => { clearTimeout(t); resolve({ code, out, err }); });
    p.on('error', (e) => { clearTimeout(t); resolve({ code: -1, out, err: String(e) }); });
  });
}

// ── Channel 1: the profile the model is allowed to see ──────────────────────
//
// Emits SHAPE, never content: name, dtype, distinct count, missingness, and a
// masked format pattern (digit→9, letter→X). "SMITH, JOHN" becomes "XXXXX, XXXX";
// an MRN becomes "999999". Enough for the model to write correct code, and
// nothing an attacker could use to identify a person.
const PROFILE_PY = `
import json, sys, re
import pandas as pd
def mask(v):
    s = str(v)
    if len(s) > 40: s = s[:40]
    return re.sub(r'[0-9]', '9', re.sub(r'[A-Za-z]', 'X', s))
df = pd.read_csv(sys.argv[1], low_memory=False)
cols = []
for c in df.columns:
    s = df[c]
    nn = s.dropna()
    pats = []
    if len(nn):
        seen = []
        for v in nn.head(200):
            m = mask(v)
            if m not in seen:
                seen.append(m)
            if len(seen) >= 3: break
        pats = seen
    cols.append({
        "name": str(c),
        "dtype": str(s.dtype),
        "n_distinct": int(s.nunique(dropna=True)),
        "missing_frac": round(float(s.isna().mean()), 4),
        "format_examples": pats,
    })
print(json.dumps({"rows": int(len(df)), "cols": int(df.shape[1]), "columns": cols}))
`;

export async function safeProfile(realPath) {
  const f = path.join(os.tmpdir(), `sphere-profile-${randomUUID()}.py`);
  fs.writeFileSync(f, PROFILE_PY);
  try {
    // The profiler itself reads the real file, so it runs WITHOUT network and
    // its output is a JSON document we construct — the raw file never becomes a
    // tool result.
    const r = await run('/usr/bin/sandbox-exec', [
      '-p', `(version 1)(allow default)(deny network*)`,
      python(), f, realPath,
    ]);
    if (r.code !== 0) return { error: 'profile_failed', detail: firstLine(r.err) };
    return JSON.parse(r.out);
  } finally {
    try { fs.unlinkSync(f); } catch {}
  }
}

export function python() {
  for (const p of ['/opt/homebrew/bin/python3', '/usr/local/bin/python3', '/usr/bin/python3']) {
    if (fs.existsSync(p)) return p;
  }
  return 'python3';
}

// ── The error channel is a data channel ─────────────────────────────────────
//
// A traceback will happily print KeyError: 'MRN_00423', or a pandas message
// quoting the offending value. Anything derived from a REAL run is reduced to an
// exception class and nothing else before it can reach the model.
export function scrubError(text) {
  const m = String(text || '').match(/([A-Za-z_]*(?:Error|Exception|Warning))\b/g);
  const cls = m && m.length ? m[m.length - 1] : 'Error';
  return `${cls} (detail withheld: raised while executing against real data)`;
}

export function firstLine(s) {
  return String(s || '').split('\n').filter(Boolean).slice(-1)[0] || '';
}
