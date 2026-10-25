'use strict';
const fs = require('fs');
const path = require('path');
const {createHash, randomFillSync} = require('crypto');

function runtimeEnvironment(env = process.env) {
  // Go's bootstrap has an 8 KiB argv+environment region. The engine only
  // needs filesystem locations and timezone. Authorized child processes
  // inherit the complete original Node environment through the host adapter.
  const result = {HOME:env.HOME || require('os').homedir(), TMPDIR:require('os').tmpdir()};
  if (env.TZ) result.TZ = env.TZ;
  return result;
}

function verifyRuntime(directory, version) {
  const manifestPath = path.join(directory,'manifest.json');
  if (!fs.lstatSync(manifestPath).isFile() || fs.statSync(manifestPath).size > 16384) throw Error('Invalid npm runtime manifest');
  const manifest = JSON.parse(fs.readFileSync(manifestPath,'utf8'));
  if (manifest.version !== version || manifest.format !== 'go-js-wasm-v1') throw Error('npm runtime version mismatch');
  const names = ['mcpsense.wasm','wasm_exec.cjs','host.cjs','LICENSE.Go'];
  const assets = {};
  for (const name of names) {
    const file = path.join(directory,name);
    if (!fs.lstatSync(file).isFile() || fs.statSync(file).size > (64<<20)) throw Error('Invalid npm runtime asset');
    const data = fs.readFileSync(file);
    if (!manifest.files || manifest.files[name] !== createHash('sha256').update(data).digest('hex')) throw Error('npm runtime checksum mismatch: '+name);
    assets[name] = data;
  }
  return assets;
}

async function runWasm(args, directory = path.join(__dirname,'..','runtime')) {
  const pkg = require('../package.json');
  const assets = verifyRuntime(directory,pkg.version);
  if (!globalThis.crypto) globalThis.crypto = {getRandomValues:randomFillSync};
  if (!globalThis.performance) globalThis.performance = require('perf_hooks').performance;
  if (!globalThis.TextEncoder) globalThis.TextEncoder = require('util').TextEncoder;
  if (!globalThis.TextDecoder) globalThis.TextDecoder = require('util').TextDecoder;
  const adapter = require(path.join(directory,'host.cjs'));
  globalThis.fs = adapter.filesystem();
  globalThis.path = path;
  const host = adapter.createHost();
  globalThis.mcpsenseHost = host;
  require(path.join(directory,'wasm_exec.cjs'));
  const go = new Go(); let status = 0;
  go.argv = ['mcpsense',...args];
  go.env = runtimeEnvironment();
  go.exit = code => {status=code;};
  try {
    const result = await WebAssembly.instantiate(assets['mcpsense.wasm'],go.importObject);
    await go.run(result.instance);
  } finally {await host.closeAll();}
  return status;
}
module.exports = {verifyRuntime,runWasm,runtimeEnvironment};
if (require.main === module) {
  try { verifyRuntime(path.join(__dirname,'..','runtime'),require('../package.json').version); console.log('Bundled npm runtime verified.'); }
  catch(error) { console.error('Build the npm runtime before publication: '+error.message); process.exitCode=1; }
}
