'use strict';
// Explicit, networked acceptance test against the real published stable channels.
// The private old-version fixture contains the new updater; it is never published.
const fs=require('node:fs'),path=require('node:path'),assert=require('node:assert/strict');
const {execFileSync}=require('node:child_process');const {createHash}=require('node:crypto');
const root=path.resolve(__dirname,'..'),stage=fs.mkdtempSync(path.join(root,'bin','update-command-'));
function run(file,args,opts={}){return execFileSync(file,args,{cwd:stage,encoding:'utf8',windowsHide:true,timeout:300000,...opts});}
const npm=[path.dirname(process.execPath),...(process.env.PATH||'').split(path.delimiter)].flatMap(d=>[path.join(d,'node_modules/npm/bin/npm-cli.js'),path.join(d,'../lib/node_modules/npm/bin/npm-cli.js')]).find(fs.existsSync);assert.ok(npm);
const source=path.join(stage,'private-fixture');fs.cpSync(path.join(root,'npm'),source,{recursive:true});
const fixturePkg=JSON.parse(fs.readFileSync(path.join(source,'package.json'),'utf8'));fixturePkg.version='0.3.0';fs.writeFileSync(path.join(source,'package.json'),JSON.stringify(fixturePkg,null,2));
run('go',['build','-trimpath','-ldflags=-s -w -X main.version=0.3.0','-o',path.join(source,'runtime/mcpsense.wasm'),'./cmd/mcpsense'],{cwd:root,env:{...process.env,GOOS:'js',GOARCH:'wasm',CGO_ENABLED:'0'}});
const manifest=JSON.parse(fs.readFileSync(path.join(source,'runtime/manifest.json'),'utf8'));manifest.version='0.3.0';manifest.files['mcpsense.wasm']=createHash('sha256').update(fs.readFileSync(path.join(source,'runtime/mcpsense.wasm'))).digest('hex');fs.writeFileSync(path.join(source,'runtime/manifest.json'),JSON.stringify(manifest,null,2));
const prefix=path.join(stage,'npm global'),goBin=path.join(stage,'go','bin');fs.mkdirSync(goBin,{recursive:true});
const native=path.join(goBin,process.platform==='win32'?'mcpsense.exe':'mcpsense');
run('go',['build','-ldflags=-X main.version=0.3.0','-o',native,'./cmd/mcpsense'],{cwd:root});
const npmBin=process.platform==='win32'?prefix:path.join(prefix,'bin');
const env={...process.env,PATH:[goBin,npmBin,process.env.PATH].join(path.delimiter),GOBIN:goBin,npm_config_prefix:prefix,MCPSENSE_NO_UPDATE_CHECK:'1'};
const pack=JSON.parse(run(process.execPath,[npm,'pack',source,'--json','--ignore-scripts','--pack-destination',stage]))[0];
run(process.execPath,[npm,'install','--global','--prefix',prefix,path.join(stage,pack.filename),'--ignore-scripts','--no-audit','--no-fund'],{env});
const installed=path.join(prefix,process.platform==='win32'?'node_modules':'lib/node_modules','mcpsense'),runner=path.join(installed,'bin/run.js');
const plan=JSON.parse(run(process.execPath,[runner,'update','--plan-json'],{env}));assert.equal(plan.installed_version,'0.3.0');assert.match(plan.latest_version,/^0\.[0-9]+\.[0-9]+$/);
// A warm, valid cache proves the user-facing notice without relying on external HTTP timing.
const cache=path.join(stage,'cache'),cacheBase=path.join(cache,'mcpsense');fs.mkdirSync(cacheBase,{recursive:true});
fs.writeFileSync(path.join(cacheBase,'updates.json'),JSON.stringify({checked_at:new Date().toISOString(),latest_version:plan.latest_version}));
const noticeEnv={...env,CI:'',MCPSENSE_NO_UPDATE_CHECK:'',LOCALAPPDATA:cache,XDG_CACHE_HOME:cache};
const noticeCode='process.stdout.isTTY=true;process.stderr.isTTY=true;require(process.argv[1]).runCLI(["version"]).then(c=>process.exit(c))';
const notice= require('node:child_process').spawnSync(process.execPath,['-e',noticeCode,runner],{env:noticeEnv,encoding:'utf8',windowsHide:true,timeout:30000});
assert.equal(notice.status,0);assert.equal(notice.stdout.trim(),'mcpsense v0.3.0');assert.ok(notice.stderr.includes('MCPSense update available: 0.3.0 → '+plan.latest_version));
fs.writeFileSync(path.join(stage,'notice.log'),notice.stderr);
run(process.execPath,[runner,'init','--example'],{env});
const quietCases=[
  {args:['version','--no-update-check']},
  {args:['version'],env:{CI:'true'}},
  {args:['version'],env:{MCPSENSE_NO_UPDATE_CHECK:'1'}},
  {args:['version'],piped:true},
  {args:['--help']},
  {args:['scan',path.join(stage,'mcp.json'),'--offline','--no-baseline']},
  {args:['scan',path.join(stage,'mcp.json'),'--format=json','--no-baseline']},
  {args:['scan',path.join(stage,'mcp.json'),'--format=sarif','--no-baseline']},
];
for(const c of quietCases){
  const code='process.stdout.isTTY='+!c.piped+';process.stderr.isTTY='+!c.piped+';require(process.argv[1]).runCLI(JSON.parse(process.argv[2])).then(c=>process.exit(c))';
  const result=require('node:child_process').spawnSync(process.execPath,['-e',code,runner,JSON.stringify(c.args)],{cwd:stage,env:{...noticeEnv,...c.env},encoding:'utf8',windowsHide:true,timeout:30000});
  assert.equal(result.status,0,JSON.stringify(c.args)+': '+result.stderr);assert.ok(!result.stderr.includes('MCPSense update available:'),JSON.stringify(c.args));
  if(c.args.includes('--format=json')||c.args.includes('--format=sarif'))JSON.parse(result.stdout);
}
// Check-only must not replace the package or the old Go executable.
run(process.execPath,[runner,'update','--check'],{env});assert.equal(JSON.parse(fs.readFileSync(path.join(installed,'package.json'))).version,'0.3.0');
const npmOutput=run(process.execPath,[runner,'update','--repair-path'],{env});fs.writeFileSync(path.join(stage,'npm-update.log'),npmOutput);
assert.equal(JSON.parse(fs.readFileSync(path.join(installed,'package.json'))).version,plan.latest_version);
assert.equal(run(process.execPath,[runner,'version'],{env}).trim(),'mcpsense v'+plan.latest_version);
assert.equal(fs.readdirSync(goBin).filter(n=>n.includes('backup')).length,1);
function plainVersion(selectedEnv) {return process.platform==='win32'?run(path.join(process.env.SystemRoot,'System32/WindowsPowerShell/v1.0/powershell.exe'),['-NoProfile','-NonInteractive','-Command','mcpsense version'],{env:selectedEnv}).trim():run('/bin/sh',['-c','mcpsense version'],{env:selectedEnv}).trim();}
assert.equal(plainVersion(env),'mcpsense v'+plan.latest_version);
// Native users retain their independent Go route; test replacement of a running executable.
const nativeDir=path.join(stage,'native-only');fs.mkdirSync(nativeDir);const active=path.join(nativeDir,path.basename(native));
run('go',['build','-ldflags=-X main.version=0.3.0','-o',active,'./cmd/mcpsense'],{cwd:root});
const nativeEnv={...process.env,PATH:[nativeDir,process.env.PATH].join(path.delimiter),MCPSENSE_NO_UPDATE_CHECK:'1'};
fs.writeFileSync(path.join(stage,'native-update.log'),run(active,['update'],{env:nativeEnv}));
assert.equal(plainVersion(nativeEnv),'mcpsense v'+plan.latest_version);
assert.equal(fs.readdirSync(nativeDir).filter(n=>n.includes('backup')).length,1);
const results={platform:process.platform,node:process.version,privateFixtureVersion:'0.3.0',publishedTarget:plan.latest_version,npmSamePrefix:true,npmPlainCommandVerified:true,nativeRunningExecutableReplaced:true,nativePlainCommandVerified:true,noticeOnStderr:true,quietNoticeJourneys:quietCases.length,checkOnlyPreservesFiles:true};
fs.writeFileSync(path.join(stage,'results.json'),JSON.stringify(results,null,2)+'\n');console.log('PASS: npm self-update, cached notice, check-only, shadow repair and native Go update.');console.log('Evidence: '+path.join(stage,'results.json'));
