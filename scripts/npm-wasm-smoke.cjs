'use strict';
// Pack and install the actual npm artifact offline, with no Go or archive tools.
const fs = require('fs'), os = require('os'), path = require('path');
const assert = require('assert/strict');
const {execFileSync, spawnSync} = require('child_process');
const root = path.resolve(__dirname, '..');
const pkg = require('../npm/package.json');
function npmCLI() {
  const directories = [path.dirname(process.execPath), ...(process.env.PATH || '').split(path.delimiter)];
  for (const directory of directories) {
    const candidates = [path.join(directory,'node_modules/npm/bin/npm-cli.js'), path.join(directory,'../lib/node_modules/npm/bin/npm-cli.js'), path.join(directory,'npm')];
    for (const file of candidates) {
      if (!fs.existsSync(file)) continue;
      const resolved = fs.realpathSync(file);
      if (resolved.endsWith('npm-cli.js')) return resolved;
    }
  }
  throw Error('Cannot locate the installed npm CLI');
}
function main() {
  const npm = npmCLI();
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(),'mcpsense-npm-wasm-'));
  const evidence = path.resolve(process.env.MCPSENSE_NPM_EVIDENCE || path.join(root,'bin/npm-install-wasm'));
  fs.mkdirSync(evidence,{recursive:true});
  const empty = path.join(tmp,'empty-path'); fs.mkdirSync(empty);
  const env = {...process.env, PATH:empty, npm_config_update_notifier:'false'};
  assert.equal(spawnSync('go',['version'],{env}).error?.code,'ENOENT');
  assert.equal(spawnSync('tar',['--version'],{env}).error?.code,'ENOENT');
  const options = {cwd:root,env,encoding:'utf8',windowsHide:true,timeout:120000};
  const pack = JSON.parse(execFileSync(process.execPath,[npm,'pack','./npm','--json','--ignore-scripts','--pack-destination',tmp],options))[0];
  const expected = ['package.json','README.md','LICENSE','bin/run.js','bin/wasm.js','runtime/manifest.json','runtime/host.cjs','runtime/wasm_exec.cjs','runtime/mcpsense.wasm','runtime/LICENSE.Go'];
  assert.deepEqual(pack.files.map(f=>f.path).sort(),expected.sort(),'Unexpected/missing npm package files');
  const tarball = path.join(tmp,pack.filename);
  fs.copyFileSync(tarball,path.join(evidence,pack.filename));
  fs.writeFileSync(path.join(evidence,'pack.json'),JSON.stringify(pack,null,2)+'\n');
  const prefix = path.join(tmp,'installation with spaces');
  execFileSync(process.execPath,[npm,'install','--global','--prefix',prefix,tarball,'--ignore-scripts','--offline','--cache',path.join(tmp,'cache'),'--no-audit','--no-fund'],options);
  const installed = path.join(prefix,process.platform==='win32'?'node_modules':'lib/node_modules','mcpsense');
  const runner = path.join(installed,'bin/run.js'), binary = path.join(installed,'runtime/mcpsense.wasm');
  assert.equal(execFileSync(process.execPath,[runner,'version'],options).trim(),'mcpsense v'+pkg.version);
  if (process.platform==='win32') {
    const shimEnv = {...env,PATH:path.dirname(process.execPath),MCPSENSE_NPM_SHIM:path.join(prefix,'mcpsense.cmd')};
    assert.equal(execFileSync(path.join(process.env.SystemRoot,'System32/cmd.exe'),['/d','/s','/c','""%MCPSENSE_NPM_SHIM%" version"'],{...options,env:shimEnv,windowsVerbatimArguments:true}).trim(),'mcpsense v'+pkg.version);
  } else assert.ok(fs.lstatSync(path.join(prefix,'bin/mcpsense')).isSymbolicLink());
  execFileSync(process.execPath,['--test',path.join(root,'scripts/product.test.mjs')],{...options,timeout:240000,stdio:'inherit',env:{...env,MCPSENSE_TEST_BINARY:binary,MCPSENSE_TEST_RUNNER:runner}});
  fs.writeFileSync(path.join(evidence,'installation.json'),JSON.stringify({version:pkg.version,node:process.version,platform:process.platform,noGo:true,noArchiveTools:true,offlineInstall:true,installScripts:false,tarball:pack.filename,integrity:pack.integrity,runner,binary},null,2)+'\n');
  console.log('PASS: actual npm package installed offline with no Go, no archive tools and no install scripts; installed user journeys passed.');
  console.log('Installed test runner: '+runner);
}
try {main();} catch(error) {console.error(error); process.exitCode=1;}
