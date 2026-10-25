'use strict';
// Maintainer build step only. Published packages contain every runtime asset;
// installation never invokes Go, downloads an executable or runs a build hook.
const fs = require('fs');
const path = require('path');
const {execFileSync} = require('child_process');
const {createHash} = require('crypto');
const root = path.resolve(__dirname, '..');
const output = path.join(root, 'npm', 'runtime');
const pkg = require('../npm/package.json');
const go = process.env.MCPSENSE_BUILD_GO || 'go';
const tempRoot = path.join(root, 'bin'); fs.mkdirSync(tempRoot, {recursive:true});
const stage = fs.mkdtempSync(path.join(tempRoot, 'npm-runtime-build-'));
const options = {cwd:root, encoding:'utf8', windowsHide:true};
const goroot = execFileSync(go, ['env', 'GOROOT'], options).trim();
const toolchain = execFileSync(go, ['version'], options).trim();
const bootstrap = ['lib/wasm/wasm_exec.js','misc/wasm/wasm_exec.js'].map(p => path.join(goroot,p)).find(p => fs.existsSync(p));
if (!bootstrap) throw Error('Matching Go WebAssembly runtime is unavailable');
execFileSync(go, ['build', '-trimpath', '-ldflags=-s -w -X main.version=' + pkg.version, '-o', path.join(stage,'mcpsense.wasm'), './cmd/mcpsense'],
  {...options, stdio:'inherit', env:{...process.env, GOOS:'js', GOARCH:'wasm', CGO_ENABLED:'0'}});
fs.copyFileSync(bootstrap, path.join(stage,'wasm_exec.cjs'));
fs.copyFileSync(path.join(goroot,'LICENSE'), path.join(stage,'LICENSE.Go'));
fs.copyFileSync(path.join(root,'internal/nodebridge/node.cjs'), path.join(stage,'host.cjs'));
const files = ['mcpsense.wasm','wasm_exec.cjs','host.cjs','LICENSE.Go'];
const hashes = Object.fromEntries(files.map(name => [name, createHash('sha256').update(fs.readFileSync(path.join(stage,name))).digest('hex')]));
fs.writeFileSync(path.join(stage,'manifest.json'), JSON.stringify({version:pkg.version, toolchain, format:'go-js-wasm-v1', files:hashes},null,2)+'\n');
fs.mkdirSync(output,{recursive:true});
for (const name of [...files,'manifest.json']) fs.copyFileSync(path.join(stage,name),path.join(output,name));
console.log(JSON.stringify({version:pkg.version, toolchain, output, bytes:fs.statSync(path.join(output,'mcpsense.wasm')).size, files:hashes},null,2));
// Retain build evidence under ignored bin/. No destructive directory cleanup.
