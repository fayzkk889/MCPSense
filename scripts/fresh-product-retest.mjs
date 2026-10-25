// Executes only the scanner. The authored descriptions are data, never tool calls.
import fs from 'node:fs';
import path from 'node:path';
import {createHash} from 'node:crypto';
import {spawnSync} from './cli-process.cjs';
import assert from 'node:assert/strict';

const binary = process.env.MCPSENSE_TEST_BINARY;
if (!binary) throw Error('MCPSENSE_TEST_BINARY required');
const root = path.resolve(process.env.MCPSENSE_FRESH_DIR || 'bin/product-retest-2026-10-24/fresh');
fs.mkdirSync(root, {recursive: true});
const workspace = fs.mkdtempSync(path.join(root, 'Customer project with spaces-'));
const fixture = fs.readFileSync('testdata/product-retest-2026-10-24.json');
const cases = JSON.parse(fixture).cases;
const records = [];
const wsl = process.env.MCPSENSE_ACCEPTANCE_WSL;
const linuxPath = v => v.replace(/^([A-Za-z]):[\\/]/, (_, d) => '/mnt/' + d.toLowerCase() + '/').replaceAll('\\', '/');
for (const surface of ['tool-description', 'server-instructions']) {
  for (const c of cases) {
    const manifest = {name: 'customer-records', version: '1.0.0', protocolVersion: '2025-11-25', auth: {type: 'oauth2'},
      tools: [{name: 'read_record', description: 'Read one authorized record.', inputSchema: {type: 'object', properties: {id: {type: 'string', description: 'Record identifier.', maxLength: 64}}, required: ['id'], examples: [{id: 'one'}]}}]};
    if (surface === 'tool-description') manifest.tools[0].description = c.text;
    else manifest.instructions = c.text;
    const file = path.join(workspace, c.id + '-' + surface + '.json');
    fs.writeFileSync(file, JSON.stringify(manifest));
    const args = ['scan', file, '--offline', '--no-baseline', '--format', 'json'];
    const r = spawnSync(wsl ? 'wsl' : binary, wsl ? ['-d', wsl, '--', linuxPath(binary), ...args.map(a => /^[A-Za-z]:[\\/]/.test(a) ? linuxPath(a) : a)] : args,
      {cwd: workspace, encoding: 'utf8', timeout: 35000, maxBuffer: 4 << 20, windowsHide: true});
    assert.equal(r.error, undefined, c.id); assert.ok([0, 1].includes(r.status), c.id + ': ' + r.stderr);
    const report = JSON.parse(r.stdout);
    const predicted = report.findings.some(f => f.id === 'SEC-001');
    const record = {...c, surface, predicted, outcome: c.hostile ? (predicted ? 'TP' : 'FN') : (predicted ? 'FP' : 'TN'), exit: r.status,
      rules: [...new Set(report.findings.filter(f => f.id.startsWith('SEC-')).map(f => f.id))], report};
    records.push(record);
    console.log(record.outcome + ' ' + c.id + ' ' + surface + ' ' + record.rules.join(','));
  }
}
const counts = Object.fromEntries(['TP', 'TN', 'FP', 'FN'].map(outcome => [outcome, records.filter(r => r.outcome === outcome).length]));
const result = {binary, binarySHA256: createHash('sha256').update(fs.readFileSync(binary)).digest('hex'), fixtureSHA256: createHash('sha256').update(fixture).digest('hex'),
  limitation: 'Authored examples across two surfaces; not independent samples or field accuracy. No tool or attack was executed.', counts, records};
fs.writeFileSync(path.join(workspace, 'results.json'), JSON.stringify(result, null, 2));
console.log(JSON.stringify({counts, evidence: workspace}));
if (process.env.MCPSENSE_FRESH_ENFORCE === '1' && (counts.FP || counts.FN)) process.exitCode = 1;
