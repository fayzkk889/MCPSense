// Exercise saved-baseline user workflows through the real CLI on each CI OS.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import {spawnSync} from 'node:child_process';

const binary = process.env.MCPSENSE_TEST_BINARY;
if (!binary) throw Error('MCPSENSE_TEST_BINARY must name the reviewed CLI');
const root = path.resolve(process.env.MCPSENSE_BASELINE_DIR || 'bin/baseline-acceptance');
fs.mkdirSync(root, {recursive: true});
const workspace = fs.mkdtempSync(path.join(root, 'User project with spaces-'));
const target = path.join(workspace, 'manifest.json');
const baseline = path.join(workspace, 'approved.json');
const sarif = path.join(workspace, 'report.sarif');
const wsl = process.env.MCPSENSE_ACCEPTANCE_WSL;
const records = [], results = [];
const linuxPath = value => value.replace(/^([A-Za-z]):[\\/]/, (_, drive) => '/mnt/' + drive.toLowerCase() + '/').replaceAll('\\', '/');
function run(name, args) {
  const argv = wsl ? ['-d', wsl, '--cd', linuxPath(workspace), '--', linuxPath(binary), ...args.map(a => /^[A-Za-z]:[\\/]/.test(a) ? linuxPath(a) : a)] : args;
  const r = spawnSync(wsl ? 'wsl' : binary, argv, {cwd: workspace, encoding: 'utf8', timeout: 40000, maxBuffer: 8 << 20, windowsHide: true});
  const record = {name, args, exit: r.status, error: r.error?.message, stdout: r.stdout || '', stderr: r.stderr || ''};
  records.push(record);
  assert.equal(r.error, undefined, name);
  return record;
}
function check(name, fn) {
  fn(); results.push({name, status: 'PASS'}); console.log('PASS ' + name);
}
function write(file, obj) { fs.writeFileSync(file, JSON.stringify(obj, null, 2)); }
function scan(name, extra = []) {
  const r = run(name, ['scan', target, '--offline', '--checks', 'SEC-001', '--baseline', baseline, '--format', 'json', ...extra]);
  assert.ok([0, 1].includes(r.exit), name + ': ' + r.stderr);
  return JSON.parse(r.stdout);
}
function fixture() {
  return {name: 'records', version: '1.0.0', description: 'Record service.', instructions: 'Use record identifiers.', auth: {type: 'oauth2'},
    tools: [{name: 'read_record', title: 'Read record', description: 'Retrieve one record.', inputSchema: {type: 'object'}, outputSchema: {type: 'object'}, annotations: {title: 'Reader'}}],
    resources: [{uri: 'record://catalog', name: 'Catalog', description: 'Available records.'}],
    prompts: [{name: 'summarize', description: 'Summarize one record.', arguments: [{name: 'record', required: true}]}]};
}
const ids = r => r.findings.filter(f => f.id.startsWith('DRIFT-')).map(f => f.id).sort();
try {
  write(target, fixture());
  check('First scan captures the expanded baseline', () => {
    const r = scan('create');
    assert.equal(r.coverage.baseline, 'created');
    assert.equal(JSON.parse(fs.readFileSync(baseline)).metadata.version, 1);
    assert.deepEqual(ids(r), []);
  });
  const approvedBytes = fs.readFileSync(baseline, 'utf8');
  const edits = [
    ['server description', 'DRIFT-011', m => {m.description += ' Changed.';}],
    ['server instructions', 'DRIFT-011', m => {m.instructions += ' Changed.';}],
    ['tool title', 'DRIFT-010', m => {m.tools[0].title += ' Changed.';}],
    ['output schema', 'DRIFT-010', m => {m.tools[0].outputSchema.description = 'Record output.';}],
    ['annotation title', 'DRIFT-008', m => {m.tools[0].annotations.title += ' Changed.';}],
    ['resource metadata', 'DRIFT-009', m => {m.resources[0].description += ' Changed.';}],
    ['new prompt', 'DRIFT-012', m => {m.prompts.push({name: 'review', description: 'Review one record.'});}],
    ['prompt description', 'DRIFT-013', m => {m.prompts[0].description += ' Changed.';}],
    ['prompt arguments', 'DRIFT-013', m => {m.prompts[0].arguments[0].required = false;}]
  ];
  for (const [name, id, edit] of edits) {
    check('Changed ' + name + ' appears in JSON and SARIF', () => {
      const m = fixture(); edit(m); write(target, m);
      const r = scan(name, ['--sarif-output', sarif]);
      const s = JSON.parse(fs.readFileSync(sarif));
      assert.deepEqual(ids(r), [id]);
      assert.deepEqual(s.runs[0].results.filter(f => f.ruleId.startsWith('DRIFT-')).map(f => f.ruleId), [id]);
      assert.deepEqual(s.runs[0].properties.coverage, r.coverage);
      assert.ok(r.coverage.baseline_fields.includes('server.instructions'));
      assert.equal(r.coverage.baseline_warning, undefined);
      assert.equal(fs.readFileSync(baseline, 'utf8'), approvedBytes);
    });
  }
  check('Unchanged target stays quiet and ordering is stable', () => {
    write(target, fixture()); assert.deepEqual(ids(scan('unchanged')), []);
    const m = fixture(); m.instructions += ' Changed.'; m.tools[0].title += ' Changed.'; m.prompts[0].description += ' Changed.'; write(target, m);
    const first = ids(scan('multiple')), second = ids(scan('repeated'));
    assert.deepEqual(first, ['DRIFT-010', 'DRIFT-011', 'DRIFT-013']); assert.deepEqual(first, second);
  });
  let legacyReport;
  check('Older v2 baseline remains usable with an explicit coverage warning', () => {
    const legacy = JSON.parse(approvedBytes); delete legacy.metadata; write(baseline, legacy);
    const original = fs.readFileSync(baseline, 'utf8');
    const m = fixture(); m.instructions += ' Changed.'; write(target, m);
    legacyReport = scan('legacy-v2'); assert.deepEqual(ids(legacyReport), []);
    assert.ok(legacyReport.coverage.baseline_warning.includes('--update-baseline'));
    assert.ok(!legacyReport.coverage.baseline_fields.includes('server.instructions'));
    const terminal = run('legacy-terminal', ['scan', target, '--offline', '--checks', 'SEC-001', '--baseline', baseline, '--no-color']);
    assert.ok(terminal.stdout.includes('these fields were not compared'));
    m.tools[0].description += ' Changed.'; write(target, m);
    assert.deepEqual(ids(scan('legacy-existing-field')), ['DRIFT-002']);
    assert.equal(fs.readFileSync(baseline, 'utf8'), original);
  });
  check('Explicit baseline update enables the new comparisons', () => {
    const r = scan('explicit-update', ['--update-baseline']); assert.equal(r.coverage.baseline, 'updated');
    const current = scan('accepted'); assert.deepEqual(ids(current), []); assert.equal(current.coverage.baseline_warning, undefined);
    const before = path.join(workspace, 'legacy-report.json'), after = path.join(workspace, 'current-report.json');
    write(before, legacyReport); write(after, current);
    assert.equal(run('refuse-different-coverage', ['verify', before, after]).exit, 2);
    const m = JSON.parse(fs.readFileSync(target)); m.instructions += ' Another change.'; write(target, m);
    assert.deepEqual(ids(scan('post-update-change')), ['DRIFT-011']);
  });
  check('Future metadata extensions fail visibly without overwriting the baseline', () => {
    const future = JSON.parse(approvedBytes); future.metadata.version = 999; write(baseline, future);
    const original = fs.readFileSync(baseline, 'utf8');
    const r = run('future-extension', ['scan', target, '--offline', '--baseline', baseline, '--format', 'json']);
    assert.equal(r.exit, 2); assert.ok(r.stderr.includes('--update-baseline'));
    assert.equal(fs.readFileSync(baseline, 'utf8'), original);
  });
} finally {
  fs.writeFileSync(path.join(workspace, 'results.json'), JSON.stringify({binary, results, invocations: records}, null, 2));
}
