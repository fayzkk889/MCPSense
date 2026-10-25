// Real CLI journeys. Synthetic cache entries test wiring without external
// dependencies; MCPSENSE_DEPENDENCY_ONLINE=1 additionally queries public OSV.
import fs from 'node:fs';
import path from 'node:path';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {spawnSync} from './cli-process.cjs';

const binary = process.env.MCPSENSE_TEST_BINARY;
if (!binary) throw Error('MCPSENSE_TEST_BINARY is required');
const root = path.resolve(process.env.MCPSENSE_DEPENDENCY_DIR || 'bin/dependency-acceptance');
fs.mkdirSync(root, {recursive: true});
const workspace = fs.mkdtempSync(path.join(root, 'Project with spaces-'));
const home = path.join(workspace, 'isolated-home');
const wsl = process.env.MCPSENSE_ACCEPTANCE_WSL;
const linuxPath = v => v.replace(/^([A-Za-z]):[\\/]/, (_, d) => '/mnt/' + d.toLowerCase() + '/').replaceAll('\\', '/');
const records = [];
function write(name, value) {
  const p = path.join(workspace, name); fs.mkdirSync(path.dirname(p), {recursive: true});
  fs.writeFileSync(p, typeof value === 'string' ? value : JSON.stringify(value)); return p;
}
function run(name, args, expected = 0) {
  const command = wsl ? 'wsl' : binary;
  const argv = wsl ? ['-d', wsl, '--cd', linuxPath(workspace), '--', 'env', 'HOME=' + linuxPath(home), 'USERPROFILE=' + linuxPath(home), linuxPath(binary), ...args.map(a => /^[A-Za-z]:[\\/]/.test(a) ? linuxPath(a) : a)] : args;
  const r = spawnSync(command, argv, {cwd: workspace, env: {...process.env, HOME: home, USERPROFILE: home}, encoding: 'utf8', timeout: 45000, maxBuffer: 12 << 20, windowsHide: true});
  records.push({name, args, exit: r.status, stdout: r.stdout || '', stderr: r.stderr || ''});
  assert.equal(r.error, undefined, name);
  assert.ok((Array.isArray(expected) ? expected : [expected]).includes(r.status), name + ': exit=' + r.status + ' ' + r.stderr);
  console.log('PASS ' + name);
  return r;
}
const scan = (name, file, options = [], expected = 0) => run(name, ['scan', file, '--no-baseline', '--format', 'json', ...options], expected);
function seed(name, version, vulns) {
  const key = createHash('sha256').update('npm|' + name + '|' + version).digest('hex');
  write('isolated-home/.mcpsense/cve-cache/' + key + '.json', {cache_version: 2, fetched_at: new Date().toISOString(), vulns});
}
const pkg = (name, version, extra = {}) => ({version, resolved: 'https://registry.npmjs.org/' + name + '/-/' + name.split('/').at(-1) + '-' + version + '.tgz', ...extra});
const lock = packages => ({lockfileVersion: 3, packages: {'': {name: 'synthetic-product-fixture'}, ...packages}});
const inv = write('package-lock.json', lock({
  'node_modules/outer': pkg('outer', '1.0.0'),
  'node_modules/outer/node_modules/lodash': pkg('lodash', '4.17.20'),
  'node_modules/lodash': pkg('lodash', '4.17.21'),
  'node_modules/duplicate/node_modules/lodash': pkg('lodash', '4.17.20')
}));
try {
  seed('outer', '1.0.0', []); seed('lodash', '4.17.21', []);
  seed('lodash', '4.17.20', [{ID: 'SYNTHETIC-TRANSITIVE-ADVISORY', Summary: 'Synthetic cache wiring test, not a published vulnerability.', CVSS: 7.5}]);
  let r = scan('beginner lockfile auto-detection', inv, [], 1);
  let report = JSON.parse(r.stdout);
  assert.equal(report.coverage.advisories, 'completed');
  assert.equal(report.dependencies.packages.length, 4);
  assert.equal(report.findings.length, 2);
  assert.equal(new Set(report.findings.map(f => f.location.tool_name)).size, 2);
  assert.ok(report.findings.every(f => f.location.file.endsWith('package-lock.json')));
  assert.equal(report.dependencies.sha256, createHash('sha256').update(fs.readFileSync(inv)).digest('hex'));
  const project = path.dirname(write('source/server.js', 'export const server = {};\n'));
  r = scan('expert combined project and explicit inventory', project, ['--dependencies', inv, '--checks', 'CVE-001'], 1);
  report = JSON.parse(r.stdout);
  assert.ok(report.coverage.surfaces.includes('source') && report.coverage.surfaces.includes('dependencies'));
  const before = write('before.json', report);
  r = scan('offline inventory skips cached advisories', inv, ['--offline']);
  assert.equal(JSON.parse(r.stdout).coverage.advisories, 'skipped');
  assert.equal(JSON.parse(r.stdout).findings.length, 0);
  r = run('terminal explains declared coverage', ['scan', inv, '--offline', '--no-baseline', '--no-color']);
  assert.match(r.stdout, /4 declared entries; 0 unresolved/);
  assert.match(r.stdout, /installed code and effective security settings are not verified/);
  const unknown = write('unsupported.json', lock({'node_modules/private': {version: '1.0.0', resolved: 'https://user:PRIVATE_SENTINEL@private.invalid/package.tgz'}}));
  r = scan('unsupported identity fails before online query', unknown, ['--mode', 'dependencies'], 2);
  assert.match(r.stderr, /unresolved identities/); assert.ok(!r.stderr.includes('PRIVATE_SENTINEL'));
  r = scan('offline inspection explains unsupported identity', unknown, ['--mode', 'dependencies', '--offline']);
  assert.equal(JSON.parse(r.stdout).dependencies.packages[0].unresolved, 'unverified_registry_source');
  assert.ok(!r.stdout.includes('PRIVATE_SENTINEL'));
  const ranges = write('package.json', {dependencies: {lodash: '^4.17.0'}});
  scan('package ranges cannot masquerade as resolved inventory', ranges, ['--mode', 'dependencies', '--offline'], 2);
  const malformed = write('bad.json', '{"lockfileVersion":3,"packages":{},"packages":{}}');
  scan('duplicate lockfile keys fail visibly', malformed, ['--mode', 'dependencies', '--offline'], 2);
  const truncated = write('truncated.json', lock({'': {dependencies: {missing: '^1.0.0'}}}));
  scan('missing required dependency fails before advisory query', truncated, ['--mode', 'dependencies'], 2);
  r = scan('offline inventory exposes missing required dependency', truncated, ['--mode', 'dependencies', '--offline']);
  assert.equal(JSON.parse(r.stdout).dependencies.packages[0].unresolved, 'missing_required_dependency');
  const oversized = write('large.json', ' '.repeat((4 << 20) + 1));
  scan('oversized lockfile fails visibly', oversized, ['--mode', 'dependencies', '--offline'], 2);
  const keep = fs.readFileSync(inv);
  scan('output cannot overwrite explicit inventory', project, ['--dependencies', inv, '--output', inv, '--offline'], 2);
  assert.deepEqual(fs.readFileSync(inv), keep);
  scan('two inventory selectors fail visibly', inv, ['--dependencies', inv, '--offline'], 2);
  const sarif = path.join(workspace, 'dependencies.sarif');
  scan('SARIF preserves inventory and locations', inv, ['--sarif-output', sarif], 1);
  const sarifReport = JSON.parse(fs.readFileSync(sarif));
  assert.equal(sarifReport.runs[0].properties.dependencies.packages.length, 4);
  assert.ok(sarifReport.runs[0].results.every(f => f.locations[0].physicalLocation.artifactLocation.uri.endsWith('package-lock.json')));
  write('package-lock.json', lock({
    'node_modules/outer': pkg('outer', '1.0.0'),
    'node_modules/outer/node_modules/lodash': pkg('lodash', '4.17.21'),
    'node_modules/lodash': pkg('lodash', '4.17.21'),
    'node_modules/duplicate/node_modules/lodash': pkg('lodash', '4.17.21')
  }));
  r = scan('fixed nested versions clear advisory matches', project, ['--dependencies', inv, '--checks', 'CVE-001']);
  const after = write('after.json', JSON.parse(r.stdout));
  r = run('same-scope version upgrade verifies', ['verify', before, after]);
  assert.equal(JSON.parse(r.stdout).resolved.length, 2);
  write('package-lock.json', lock({}));
  r = scan('removed inventory entries have different scope', project, ['--dependencies', inv, '--checks', 'CVE-001']);
  const removed = write('removed.json', JSON.parse(r.stdout));
  run('removing dependencies cannot claim equivalent remediation', ['verify', before, removed], 2);
  if (process.env.MCPSENSE_DEPENDENCY_ONLINE === '1') {
    // Clear synthetic entries; these public-only queries validate real advisory applicability.
    fs.rmSync(path.join(home, '.mcpsense'), {recursive: true, force: true});
    for (const [name, version, id, present] of [
      ['lodash', '4.17.20', 'GHSA-35jh-r3h4-6jhm', true],
      ['lodash', '4.17.21', 'GHSA-35jh-r3h4-6jhm', false],
      ['@modelcontextprotocol/sdk', '1.31.0', 'GHSA-46jr-4wx8-v453', true],
      ['@modelcontextprotocol/sdk', '1.32.0', 'GHSA-46jr-4wx8-v453', false]
    ]) {
      const file = write('online-' + name.replaceAll('/', '-') + '-' + version + '.json', lock({['node_modules/' + name]: pkg(name, version)}));
      const result = JSON.parse(scan('real OSV ' + name + '@' + version, file, ['--mode', 'dependencies'], [0, 1]).stdout);
      assert.equal(result.coverage.advisories, 'completed');
      assert.equal(result.findings.some(f => f.description.includes(id)), present, name + '@' + version + ' ' + id);
    }
  }
} finally {
  fs.writeFileSync(path.join(workspace, 'results.json'), JSON.stringify({binary, sha256: createHash('sha256').update(fs.readFileSync(binary)).digest('hex'), syntheticCache: true, invocations: records}, null, 2));
}
