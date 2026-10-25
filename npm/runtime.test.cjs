'use strict';
const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs'), path = require('path'), os = require('os');
const {createHash} = require('crypto');
const {spawnSync} = require('child_process');
const {verifyRuntime} = require('./bin/wasm.js');
const version = require('./package.json').version;
test('runtime verification rejects missing, corrupt, oversized and mixed assets',()=>{
  const dir = fs.mkdtempSync(path.join(os.tmpdir(),'mcpsense-runtime-'));
  const names = ['mcpsense.wasm','wasm_exec.cjs','host.cjs','LICENSE.Go'];
  const files = {};
  for (const name of names) {fs.writeFileSync(path.join(dir,name),name); files[name]=createHash('sha256').update(name).digest('hex');}
  const manifest = {version,format:'go-js-wasm-v1',files};
  const save = () => fs.writeFileSync(path.join(dir,'manifest.json'),JSON.stringify(manifest)); save();
  assert.equal(Object.keys(verifyRuntime(dir,version)).length,4);
  fs.writeFileSync(path.join(dir,'host.cjs'),'corrupt');assert.throws(()=>verifyRuntime(dir,version),/checksum/);fs.writeFileSync(path.join(dir,'host.cjs'),'host.cjs');
  manifest.version='0.0.0';save();assert.throws(()=>verifyRuntime(dir,version),/version/);manifest.version=version;save();
  fs.truncateSync(path.join(dir,'mcpsense.wasm'),(64<<20)+1);assert.throws(()=>verifyRuntime(dir,version),/Invalid/);fs.writeFileSync(path.join(dir,'mcpsense.wasm'),'mcpsense.wasm');
  fs.unlinkSync(path.join(dir,'LICENSE.Go'));assert.throws(()=>verifyRuntime(dir,version));
  fs.writeFileSync(path.join(dir,'manifest.json'),' '.repeat(16385));assert.throws(()=>verifyRuntime(dir,version),/manifest/);
});
test('built engine version and offline scan use the packaged Node entrypoint', {skip:!process.env.MCPSENSE_TEST_WASM},()=>{
  verifyRuntime(path.join(__dirname,'runtime'),version);
  const run = args => spawnSync(process.execPath,[path.join(__dirname,'bin/run.js'),...args],{encoding:'utf8',timeout:30000});
  let result=run(['version']);assert.equal(result.status,0,result.stderr);assert.equal(result.stdout.trim(),'mcpsense v'+version);
  result=run(['scan',path.resolve('testdata/compliant_server/manifest.json'),'--offline','--no-baseline','--format','json']);
  assert.equal(result.status,0,result.stderr);assert.equal(JSON.parse(result.stdout).coverage.state,'completed');
});
