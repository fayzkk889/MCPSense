'use strict';
// Installation management uses Node only. Never execute an unidentified PATH file.
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const crypto = require('node:crypto');
const {spawnSync} = require('node:child_process');
const modulePath = 'github.com/fayzkk889/MCPSense';
const stable = /^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$/;
function compare(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string' || a.length > 64 || b.length > 64 || !stable.test(a) || !stable.test(b)) throw Error('Invalid stable release version');
  const x = a.split('.'), y = b.split('.');
  for (let i = 0; i < 3; i++) if (x[i] !== y[i]) return x[i].length === y[i].length ? (x[i] < y[i] ? -1 : 1) : (x[i].length < y[i].length ? -1 : 1);
  return 0;
}
function same(a, b) { return process.platform === 'win32' ? path.resolve(a).toLowerCase() === path.resolve(b).toLowerCase() : path.resolve(a) === path.resolve(b); }
function exists(file) { try { fs.lstatSync(file); return true; } catch (e) { if (e.code === 'ENOENT') return false; throw e; } }
function regular(file) {
  const st = fs.lstatSync(file);
  if (!st.isFile() || st.nlink !== 1 || st.size > 64 * 1024 * 1024 || !same(fs.realpathSync(file), file)) throw Error('Refusing linked, oversized or non-regular command: ' + file);
  return st;
}
function hash(bytes) { return crypto.createHash('sha256').update(bytes).digest('hex'); }
function goVersion(bytes, platform = process.platform) {
  // Go 1.18+ inline build info. Reject unsupported/malformed metadata without executing it.
  const magic = Buffer.from('\xff Go buildinf:', 'latin1');
  let start = bytes.indexOf(magic);
  while (start >= 0 && start % 16 !== 0) start = bytes.indexOf(magic, start + 1);
  if (start < 0 || start + 32 > bytes.length || !(bytes[start + 15] & 2) || ![4, 8].includes(bytes[start + 14])) throw Error('Not an identified MCPSense Go executable');
  let offset = start + 32;
  function str() {
    let n = 0, shift = 0;
    for (let i = 0; i < 4; i++) {
      if (offset >= bytes.length) break;
      const c = bytes[offset++]; n += (c & 127) * 2 ** shift; shift += 7;
      if (!(c & 128)) {
        if (n > 65536 || offset + n > bytes.length) break;
        const s = bytes.subarray(offset, offset + n); offset += n; return s;
      }
    }
    throw Error('Malformed Go build information');
  }
  str(); let mod = str();
  if (mod.length < 33 || mod[mod.length - 17] !== 10) throw Error('Malformed Go module information');
  mod = mod.subarray(16, -16).toString('utf8');
  const lines = mod.split('\n');
  const goos = {win32:'windows', darwin:'darwin', linux:'linux'}[platform];
  if (!lines.includes('path\t' + modulePath + '/cmd/mcpsense') || !lines.includes('build\tGOOS=' + goos)) throw Error('Command belongs to another module or platform');
  const modules = lines.filter(l => l.startsWith('mod\t'));
  if (modules.length !== 1 || modules[0].split('\t')[1] !== modulePath) throw Error('Command belongs to another module');
  let v = modules[0].split('\t')[2].replace(/^v/, '');
  // Source/archive builds may carry a VCS pseudo-version instead of (devel).
  // Their explicit stable linker version is also used by the Go CLI.
  if (v.length > 64 || !stable.test(v)) {
    const flags = lines.filter(l => l.startsWith('build\t-ldflags='));
    const match = flags.length === 1 && flags[0].slice(15).replace(/^"|"$/g, '').match(/(?:^|\s)-X(?:\s+|=)main\.version=([0-9]+\.[0-9]+\.[0-9]+)(?:\s|$)/);
    if (!match) throw Error('Unknown development build version');
    v = match[1];
  }
  compare(v, v); return v;
}
function layout(prefix) {
  return {root:path.join(prefix, process.platform === 'win32' ? 'node_modules' : 'lib/node_modules', 'mcpsense'), bin:process.platform === 'win32' ? prefix : path.join(prefix, 'bin')};
}
function bridge(entry, node = process.execPath) {
  function quote(s) { if (/[\r\n"]/.test(s)) throw Error('Unsupported command path'); return '"' + s.replace(/%/g, '%%') + '"'; }
  return '@echo off\r\nrem MCPSENSE_NPM_BRIDGE_V1\r\nsetlocal DisableDelayedExpansion\r\n' + quote(node) + ' ' + quote(entry) + ' %*\r\n';
}
function commandIn(dir) {
  const names = process.platform === 'win32' ? ['mcpsense.exe','mcpsense.com','mcpsense.cmd','mcpsense.bat','mcpsense.ps1','mcpsense'] : ['mcpsense'];
  return names.map(n => path.join(dir,n)).filter(exists);
}
function pathDirs(env) { return (env.PATH || env.Path || '').split(path.delimiter).filter(Boolean).map(d => path.resolve(d.replace(/^"|"$/g,''))); }
function firstCommand(env) {
  for (const dir of pathDirs(env)) { const files = commandIn(dir); if (files.length) return {dir, files}; }
  return null;
}
function allowedGoDir(dir, env) {
  const roots = [path.join(os.homedir(),'go','bin')];
  if (env.GOBIN && path.isAbsolute(env.GOBIN)) roots.push(env.GOBIN);
  if (env.GOPATH) roots.push(...env.GOPATH.split(path.delimiter).filter(path.isAbsolute).map(d => path.join(d,'bin')));
  return roots.some(r => same(r,dir));
}
function repair({root, prefix, version, env = process.env, rename = fs.renameSync}) {
  const own = layout(prefix), entry = path.join(root,'bin/run.js');
  if (!same(root,own.root)) throw Error('Not the selected global npm installation');
  // An isolated --prefix installation must not modify commands in the real user's PATH.
  if (!pathDirs(env).some(d => same(d,own.bin))) return {skipped:'Global npm command directory is not on PATH: ' + own.bin};
  const first = firstCommand(env);
  if (!first) throw Error('Installed command is not on PATH');
  if (same(first.dir,own.bin)) {
    if (process.platform === 'win32') {
      for (const file of first.files) {
        if (!['mcpsense','mcpsense.cmd','mcpsense.ps1'].includes(path.basename(file))) throw Error('Unknown command in npm prefix: ' + file);
        regular(file);
        if (!fs.readFileSync(file,'utf8').replaceAll('\\','/').includes('node_modules/mcpsense/bin/run.js')) throw Error('Unknown npm command shim: ' + file);
      }
    } else if (first.files.length !== 1 || !fs.lstatSync(first.files[0]).isSymbolicLink() || !same(fs.realpathSync(first.files[0]),entry)) throw Error('Unknown command in npm prefix');
    return {command:path.join(own.bin,process.platform === 'win32' ? 'mcpsense.cmd' : 'mcpsense')};
  }
  const expected = process.platform === 'win32' ? bridge(entry) : entry;
  if (process.platform === 'win32' && first.files.length === 1 && first.files[0].endsWith('.cmd')) {
    regular(first.files[0]);
    if (fs.readFileSync(first.files[0],'utf8') === expected) return {command:first.files[0]};
  } else if (process.platform !== 'win32' && first.files.length === 1 && fs.lstatSync(first.files[0]).isSymbolicLink() && same(fs.realpathSync(first.files[0]),entry)) return {command:first.files[0]};
  if (first.files.length !== 1 || !allowedGoDir(first.dir,env)) throw Error('Another command takes precedence; preserved for review: ' + first.files.join(', '));
  const target = first.files[0];
  if (path.basename(target) !== (process.platform === 'win32' ? 'mcpsense.exe' : 'mcpsense')) throw Error('Unknown command preserved: ' + target);
  regular(target);
  const bytes = fs.readFileSync(target), old = goVersion(bytes);
  if (compare(old,version) === 0) return {command:target};
  if (compare(old,version) > 0) throw Error('A newer Go installation takes precedence; preserved: ' + target);
  const backup = target + '.mcpsense-backup-' + crypto.randomUUID();
  const replacement = process.platform === 'win32' ? path.join(first.dir,'mcpsense.cmd') : target;
  // Reserve before the rename; never overwrite an existing command or backup.
  fs.writeFileSync(backup,'',{flag:'wx'});
  let moved = false, created = false;
  try {
    regular(target);
    if (hash(fs.readFileSync(target)) !== hash(bytes)) throw Error('Command changed during installation');
    rename(target,backup); moved = true;
    if (process.platform === 'win32') fs.writeFileSync(replacement,expected,{flag:'wx'});
    else fs.symlinkSync(entry,replacement);
    created = true;
    const resolved = firstCommand(env);
    if (!resolved || resolved.files.length !== 1 || !same(resolved.files[0],replacement)) throw Error('Another command still takes precedence');
    return {command:replacement, backup, previous:old};
  } catch (e) {
    if (created && exists(replacement)) {
      const ours = process.platform === 'win32' ? fs.readFileSync(replacement,'utf8') === expected : fs.lstatSync(replacement).isSymbolicLink() && fs.readlinkSync(replacement) === expected;
      if (ours) fs.unlinkSync(replacement);
    }
    if (moved && !exists(target)) { try { rename(backup,target); } catch (restore) { e.message += '; backup retained at ' + backup + ': ' + restore.message; } }
    if (!moved) fs.unlinkSync(backup);
    throw e;
  }
}
function runNode(args, opts = {}) {
  const result = spawnSync(process.execPath,args,{encoding:'utf8',windowsHide:true,shell:false,timeout:120000,maxBuffer:1024*1024,...opts});
  if (result.error || result.status !== 0) throw Error(result.error?.message || (result.stderr || result.stdout || 'Child process failed').trim());
  return result.stdout;
}
function verify(root, version) {
  runNode([path.join(root,'bin/wasm.js'),'--verify']);
  // Child output is piped, so automatic checks are off without requiring a flag
  // that an earlier published target might not implement.
  if (runNode([path.join(root,'bin/run.js'),'version']).trim() !== 'mcpsense v' + version) throw Error('Installed runtime failed version verification');
}
function npmCLI() {
  for (const dir of [path.dirname(process.execPath), ...pathDirs(process.env)]) {
    for (const file of [path.join(dir,'node_modules/npm/bin/npm-cli.js'),path.join(dir,'../lib/node_modules/npm/bin/npm-cli.js'),path.join(dir,'npm')]) {
      if (exists(file)) { const resolved = fs.realpathSync(file); if (resolved.endsWith(path.join('npm','bin','npm-cli.js'))) return resolved; }
    }
  }
  throw Error('Cannot locate npm; use the npm installation that owns this global command');
}
function report(result) {
  if (result.skipped) throw Error(result.skipped + '; add that directory to PATH, then retry');
  console.error('Command: ' + result.command);
  if (result.backup) console.error('Previous Go executable preserved: ' + result.backup);
}
async function update(args) {
  const root = path.resolve(__dirname,'..'), pkg = JSON.parse(fs.readFileSync(path.join(root,'package.json'),'utf8'));
  console.error('Checking published MCPSense releases...');
  const plan = JSON.parse(runNode([path.join(root,'bin/run.js'),...args,'--plan-json','--no-update-check']));
  if (plan.schema_version !== 1 || plan.installed_version !== pkg.version) throw Error('Invalid update plan');
  if (compare(pkg.version,plan.latest_version) > 0) throw Error('Refusing to downgrade a newer installation');
  const npm = npmCLI();
  const prefix = runNode([npm,'prefix','--global'],{cwd:os.homedir()}).trim();
  if (!prefix || !same(layout(prefix).root,root)) throw Error('This command is not in npm’s configured global prefix; select the owning npm installation first. No files changed.');
  if (!pathDirs(process.env).some(d => same(d,layout(prefix).bin))) throw Error('The global npm command directory must be on PATH before updating');
  if (pkg.version !== plan.latest_version) {
    console.error('Updating ' + pkg.version + ' → ' + plan.latest_version + ' using npm...');
    runNode([npm,'install','--global','--prefix',prefix,'mcpsense@' + plan.latest_version,'--registry=https://registry.npmjs.org/','--strict-ssl=true','--ignore-scripts','--no-audit','--no-fund'],{cwd:os.homedir(),stdio:'inherit',timeout:300000});
  }
  verify(root,plan.latest_version);
  report(repair({root,prefix,version:plan.latest_version}));
  console.log('Updated: mcpsense v' + plan.latest_version);
  return 0;
}
function postinstall() {
  const root = path.resolve(__dirname,'..'), prefix = process.env.npm_config_global_prefix;
  // npm sets global=true for -g; local/project/npx installs cannot migrate global files.
  if (process.env.npm_config_global !== 'true' || !prefix || !same(root,layout(prefix).root)) return;
  const version = JSON.parse(fs.readFileSync(path.join(root,'package.json'),'utf8')).version;
  verify(root,version);
  const result = repair({root,prefix,version});
  if (result.skipped) { console.error('MCPSense: ' + result.skipped); return; }
  report(result);
}
module.exports = {compare,goVersion,bridge,repair,layout,firstCommand,verify,update,postinstall};
if (require.main === module) {
  try { if (process.argv[2] !== 'postinstall') throw Error('Unsupported management action'); postinstall(); }
  catch (e) { console.error('MCPSense installation conflict: ' + e.message + '\nNo PATH or security settings were changed.'); process.exitCode = 1; }
}
