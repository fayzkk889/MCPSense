'use strict';
const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs'), os = require('node:os'), path = require('node:path');
const {compare,goVersion,repair,bridge,layout} = require('./bin/manage.cjs');
function varint(n) { const b=[]; do { let v=n&127; n=Math.floor(n/128); if(n)v|=128; b.push(v); } while(n); return Buffer.from(b); }
function goFixture(v='0.3.0', module='github.com/fayzkk889/MCPSense', extra='') {
  const text=Buffer.from(`path\t${module}/cmd/mcpsense\nmod\t${module}\tv${v}\th1:test\nbuild\tGOOS=${{win32:'windows',linux:'linux',darwin:'darwin'}[process.platform]}\n${extra}`);
  const framed=Buffer.concat([Buffer.alloc(16,255),text,Buffer.alloc(16,255)]);
  const header=Buffer.alloc(32);Buffer.from('\xff Go buildinf:','latin1').copy(header);header[14]=8;header[15]=2;
  return Buffer.concat([header,varint(6),Buffer.from('go1.27'),varint(framed.length),framed]);
}
function setup(t) {
  const tmp=fs.mkdtempSync(path.join(os.tmpdir(),'mcpsense-handoff-')); t.after(()=>fs.rmSync(tmp,{recursive:true,force:true}));
  const prefix=path.join(tmp,'npm with spaces'),own=layout(prefix),go=path.join(tmp,'go','bin');
  fs.mkdirSync(path.join(own.root,'bin'),{recursive:true});fs.mkdirSync(own.bin,{recursive:true});fs.mkdirSync(go,{recursive:true});
  const entry=path.join(own.root,'bin/run.js');fs.writeFileSync(entry,'#!/usr/bin/env node\n');
  const target=path.join(go,process.platform==='win32'?'mcpsense.exe':'mcpsense');fs.writeFileSync(target,goFixture());
  return {prefix,root:own.root,version:'0.4.5',target,go,entry,env:{PATH:go+path.delimiter+own.bin,GOBIN:go}};
}
test('stable comparison rejects control text, prereleases and overflow tricks',()=>{
  assert.equal(compare('0.10.0','0.9.9'),1);assert.equal(compare('999999999999999999999.0.0','1.0.0'),1);
  for(const v of ['01.0.0','dev','1.0.0-beta','1.0.0\n','1.0.0;bad','1'.repeat(65)+'.0.0'])assert.throws(()=>compare(v,'1.0.0'));
});
test('Go metadata is parsed without execution and malformed/foreign data is refused',()=>{
  assert.equal(goVersion(goFixture()),'0.3.0');
  assert.equal(goVersion(goFixture('0.4.5-0.20261101-test+dirty',undefined,'build\t-ldflags="-s -w -X main.version=0.3.0"\n')),'0.3.0');
  for(const data of [Buffer.from('not executable'),goFixture().subarray(0,40),goFixture('0.3.0','example.org/unrelated'),goFixture('999.0.0-beta')])assert.throws(()=>goVersion(data));
});
test('older Go command is preserved byte for byte, handed to npm and repeat repair is idempotent',t=>{
  const o=setup(t),before=fs.readFileSync(o.target);fs.writeFileSync(path.join(o.go,'unrelated-tool'),'untouched');
  const result=repair(o);assert.deepEqual(fs.readFileSync(result.backup),before);assert.equal(fs.readFileSync(path.join(o.go,'unrelated-tool'),'utf8'),'untouched');
  if(process.platform==='win32')assert.equal(fs.readFileSync(result.command,'utf8'),bridge(o.entry));else assert.equal(fs.realpathSync(result.command),o.entry);
  assert.equal(repair(o).command,result.command);assert.equal(fs.readdirSync(o.go).filter(n=>n.includes('backup')).length,1);
});
test('local/isolated prefix does not migrate a global command',t=>{
  const o=setup(t);o.env.PATH=o.go;assert.ok(repair(o).skipped);assert.deepEqual(fs.readFileSync(o.target),goFixture());
});
for(const kind of ['unknown','newer','equal','foreign-directory','symlink','hardlink','ambiguous','locked'])test('preserves '+kind+' command and unrelated files',t=>{
  const o=setup(t);
  if(kind==='unknown')fs.writeFileSync(o.target,'do not execute or delete');
  if(kind==='newer')fs.writeFileSync(o.target,goFixture('9.0.0'));
  if(kind==='equal')fs.writeFileSync(o.target,goFixture(o.version));
  if(kind==='foreign-directory')o.env.GOBIN=path.dirname(o.go);
  if(kind==='ambiguous')fs.writeFileSync(path.join(o.go,process.platform==='win32'?'mcpsense.cmd':'mcpsense.exe'),'other command');
  if(kind==='symlink') {fs.renameSync(o.target,o.target+'.actual');try{fs.symlinkSync(o.target+'.actual',o.target);}catch(e){if(e.code==='EPERM'){t.skip('symlink privilege unavailable');return;}throw e;}}
  if(kind==='hardlink')fs.linkSync(o.target,o.target+'.hardlink');
  if(kind==='locked')o.rename=()=>{throw Object.assign(Error('locked'),{code:'EBUSY'});};
  const before=fs.readFileSync(o.target);
  if(kind==='equal')assert.equal(repair(o).command,o.target);
  else if(kind==='ambiguous'&&process.platform!=='win32')assert.ok(repair(o).backup); // .exe is not a Unix command candidate.
  else assert.throws(()=>repair(o));
  if(!(kind==='ambiguous'&&process.platform!=='win32'))assert.deepEqual(fs.readFileSync(o.target),before);
  assert.equal(fs.readdirSync(o.go).filter(n=>n.includes('backup')).length,kind==='ambiguous'&&process.platform!=='win32'?1:0);
});
test('bridge rejects line breaks and quotes and disables delayed expansion',()=>{
  assert.throws(()=>bridge('bad\npath'));assert.throws(()=>bridge('bad"path'));
  const text=bridge('C:\\a & b % p !\\run.js');assert.ok(text.includes('DisableDelayedExpansion'));assert.ok(text.includes('%% p !'));assert.ok(!text.includes('call '));
});
