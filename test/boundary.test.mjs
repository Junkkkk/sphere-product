// Boundary tests — these ATTACK the server rather than exercising it.
//
// Each case declares what "blocked" actually looks like for that attack, because
// the shapes differ: reading a denied file raises, listing a denied directory
// returns empty, and a scrubbed environment yields an empty key list. An earlier
// version of this file used "did it error?" as the single criterion and reported
// two false leaks — the check has to match the mechanism.
//
// Run: node test/boundary.test.mjs

import { spawn } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const SERVER = path.join(HERE, '..', 'src', 'server.js');
const REAL = process.env.SPHERE_TEST_CSV ||
  path.join(HERE, 'fixtures', 'sample.csv');   // override with SPHERE_TEST_CSV

function rpc(messages, env = {}) {
  return new Promise((resolve) => {
    const p = spawn(process.execPath, [SERVER], { env: { ...process.env, ...env } });
    let out = '';
    p.stdout.on('data', (d) => { out += d; });
    p.on('close', () => {
      const byId = {};
      for (const line of out.split('\n')) {
        if (!line.trim()) continue;
        try { const m = JSON.parse(line); if (m.id != null) byId[m.id] = m; } catch {}
      }
      resolve(byId);
    });
    p.stdin.write(messages.map((m) => JSON.stringify(m)).join('\n') + '\n');
    p.stdin.end();
  });
}

const text = (m) => (m?.result?.content || [{}])[0].text || '';
const raised = (m) => !!m?.result?.isError || /Error|PermissionError|Operation not permitted/.test(text(m));

const ATTACKS = [
  {
    name: 'read the real CSV by absolute path',
    code: (real) => `print(open(${JSON.stringify(real)}).read()[:200])`,
    blocked: (m) => raised(m),
  },
  {
    name: 'read the real CSV via pandas',
    code: (real) => `import pandas as pd; print(pd.read_csv(${JSON.stringify(real)}).head(2))`,
    blocked: (m) => raised(m),
  },
  {
    name: 'list the home directory for other datasets',
    code: () => `import glob; print(glob.glob(${JSON.stringify(os.homedir())} + '/**/*.csv', recursive=True)[:5])`,
    blocked: (m) => text(m).trim() === '[]',   // denied dirs list empty, they do not raise
  },
  {
    name: 'open a network socket to exfiltrate',
    code: () => `import socket; s=socket.socket(); s.settimeout(3); s.connect(('1.1.1.1',80)); print('CONNECTED')`,
    // Do NOT string-match the success sentinel: a traceback echoes the offending
    // SOURCE LINE, so "CONNECTED" appears in the error text even though it was
    // never printed. Non-zero exit is the signal.
    blocked: (m) => !!m?.result?.isError,
  },
  {
    name: 'harvest credentials from the environment',
    code: () => `import os; print([k for k in os.environ if any(x in k.upper() for x in ('KEY','TOKEN','SECRET','PASSWORD'))])`,
    blocked: (m) => text(m).trim() === '[]',   // scrubbed env yields no such keys
  },
  {
    name: 'write outside the session directory',
    code: () => `open(${JSON.stringify(path.join(os.homedir(), 'sphere-escape.txt'))}, 'w').write('x'); print('WROTE')`,
    // Same trap, plus the definitive check: the file must not exist afterwards.
    blocked: (m) => !!m?.result?.isError && !fs.existsSync(path.join(os.homedir(), 'sphere-escape.txt')),
  },
  {
    // REGRESSION: the first profile denied only $HOME, so a dataset in /tmp,
    // /Volumes or a lab mount was readable. Then the deny missed it again because
    // /tmp resolves to /private/tmp and Seatbelt matches the resolved path.
    name: 'read a dataset OUTSIDE the home directory',
    code: () => `print(open('/private/tmp/sphere-outside-test.csv').read()[:80])`,
    blocked: (m) => raised(m),
  },
  {
    name: 'read the twin (MUST be allowed — this is the point)',
    code: () => `import os, pandas as pd; print('twin rows', len(pd.read_csv(os.environ['SPHERE_CSV'])))`,
    blocked: (m) => /twin rows \d+/.test(text(m)),   // inverted: success is the pass
    inverted: true,
  },
];

// A dataset deliberately placed outside $HOME, in a symlinked location.
fs.writeFileSync('/private/tmp/sphere-outside-test.csv', 'secret_mrn,value\n900001,42\n');

const vault = fs.mkdtempSync(path.join(os.tmpdir(), 'sphere-test-vault-'));
const msgs = [
  { jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2024-11-05', capabilities: {} } },
  { jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name: 'sphere_open', arguments: { path: REAL } } },
  { jsonrpc: '2.0', id: 3, method: 'tools/call', params: { name: 'sphere_twin', arguments: { seed: 7 } } },
  ...ATTACKS.map((a, i) => ({
    jsonrpc: '2.0', id: 100 + i, method: 'tools/call',
    params: { name: 'sphere_run', arguments: { code: a.code(REAL) } },
  })),
  { jsonrpc: '2.0', id: 900, method: 'tools/call', params: { name: 'sphere_status', arguments: {} } },
];

// The tests need a working SPHERE CLI. Look where a checkout is likely to find
// one, then bail with an instruction rather than failing seven attacks obscurely
// because no twin was ever generated.
const CLI = process.env.SPHERE_CLI || [
  path.resolve(HERE, '..', '..', 'App', 'sphere', 'sphere-cli', 'bin', 'sphere.js'),
  path.resolve(HERE, '..', '..', 'sphere-cli', 'bin', 'sphere.js'),
].find((p) => fs.existsSync(p));

if (!CLI) {
  console.log('\n  SKIP: no SPHERE CLI found. Set SPHERE_CLI to its absolute path.\n');
  process.exit(0);
}

const res = await rpc(msgs, { SPHERE_VAULT: vault, SPHERE_CLI: CLI });

let failures = 0;
console.log('\n  boundary');
if (!/rows/.test(text(res[2]))) { console.log('  FAIL  sphere_open did not profile'); failures++; }
else console.log('  ok    profile returned (shapes only)');
if (!/Twin ready/.test(text(res[3]))) { console.log('  FAIL  twin not generated'); failures++; }
else console.log('  ok    twin generated + scored');

// the profile must not contain any real cell value
const profile = text(res[2]);
const realHead = fs.readFileSync(REAL, 'utf8').split('\n').slice(1, 40);
const leaked = realHead.filter((row) => {
  const cells = row.split(',').map((c) => c.trim()).filter((c) => c.length >= 5 && !/^[0-9.]+$/.test(c));
  return cells.some((c) => profile.includes(c));
});
if (leaked.length) { console.log(`  FAIL  profile leaked ${leaked.length} real value(s)`); failures++; }
else console.log('  ok    profile contains no real cell values');

console.log('\n  attacks from inside the analysis sandbox');
ATTACKS.forEach((a, i) => {
  const m = res[100 + i];
  const pass = a.blocked(m);
  if (!pass && process.env.SPHERE_TEST_DEBUG) {
    console.log(`        got: isError=${!!m?.result?.isError} text=${JSON.stringify(text(m).slice(0, 200))}`);
  }
  const label = a.inverted ? (pass ? 'ok    ALLOWED' : 'FAIL  wrongly blocked') : (pass ? 'ok    blocked' : 'FAIL  GOT THROUGH');
  if (!pass) failures++;
  console.log(`  ${label}  ${a.name}`);
});

const status = text(res[900]);
if (!/"real_path_visible_to_model": false/.test(status)) { console.log('\n  FAIL  status exposed the real path'); failures++; }
else console.log('\n  ok    status withholds the real path');

fs.rmSync(vault, { recursive: true, force: true });
try { fs.unlinkSync('/private/tmp/sphere-outside-test.csv'); } catch {}
console.log(failures ? `\n  ${failures} FAILURE(S)\n` : '\n  all boundary tests passed\n');
process.exit(failures ? 1 : 0);
