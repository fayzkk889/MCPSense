'use strict';
// Real global npm lifecycle + command precedence, in isolated user-owned directories.
const fs=require('node:fs'),path=require('node:path'),assert=require('node:assert/strict');
const {execFileSync,spawnSync}=require('node:child_process');
const {createHash}=require('node:crypto');
const {goVersion,bridge}=require('../npm/bin/manage.cjs');
const root=path.resolve(__dirname,'..'),pkg=require('../npm/package.json');
const stage=fs.mkdtempSync(path.join(root,'bin','update-install-'));
function run(file,args,opts={}) {return execFileSync(file,args,{cwd:stage,encoding:'utf8',windowsHide:true,timeout:180000,...opts});}
const directories=[path.dirname(process.execPath),...(process.env.PATH||'').split(path.delimiter)];
const npm=directories.flatMap(d=>[path.join(d,'node_modules/npm/bin/npm-cli.js'),path.join(d,'../lib/node_modules/npm/bin/npm-cli.js')]).find(fs.existsSync);
assert.ok(npm,'npm CLI required by test harness');
const goDir=path.join(stage,'go','bin'),prefix=path.join(stage,'npm with spaces');fs.mkdirSync(goDir,{recursive:true});
const old=path.join(goDir,process.platform==='win32'?'mcpsense.exe':'mcpsense');
if(process.env.MCPSENSE_UPDATE_OLD_BINARY)fs.copyFileSync(process.env.MCPSENSE_UPDATE_OLD_BINARY,old);
else run('go',['build','-ldflags=-X main.version=0.3.0','-o',old,'./cmd/mcpsense'],{cwd:root});
const before=fs.readFileSync(old);assert.equal(goVersion(before),'0.3.0');
fs.writeFileSync(path.join(goDir,'unrelated-tool.txt'),'preserved');
const npmBin=process.platform==='win32'?prefix:path.join(prefix,'bin');
const system=process.platform==='win32'?path.join(process.env.SystemRoot,'System32'):'/usr/bin:/bin';
const tools=path.join(stage,'tools');fs.mkdirSync(tools);
// npm invokes the OS shell by name for lifecycle scripts. Keep sh, while
// excluding directories that could expose a Go compiler to installation.
if(process.platform!=='win32')fs.symlinkSync('/bin/sh',path.join(tools,'sh'));
const env={...process.env,PATH:[goDir,npmBin,path.dirname(process.execPath),process.platform==='win32'?system:tools].join(path.delimiter),GOBIN:goDir,
  npm_config_prefix:prefix,npm_config_update_notifier:'false',MCPSENSE_NO_UPDATE_CHECK:'1'};
assert.equal(spawnSync('go',['version'],{env}).error?.code,'ENOENT','npm installation must not have Go available');
function commandVersion(commandEnv=env) {
  return process.platform==='win32'
    ? run(path.join(system,'WindowsPowerShell/v1.0/powershell.exe'),['-NoProfile','-NonInteractive','-Command','mcpsense version'],{env:commandEnv}).trim()
    : run('/bin/sh',['-c','mcpsense version'],{env:commandEnv}).trim();
}
assert.equal(commandVersion(),'mcpsense v0.3.0');
const pack=JSON.parse(run(process.execPath,[npm,'pack',path.join(root,'npm'),'--json','--ignore-scripts','--pack-destination',stage]))[0];
const tarball=path.join(stage,pack.filename);
function install() {return run(process.execPath,[npm,'install','--global','--prefix',prefix,tarball,'--foreground-scripts','--no-audit','--no-fund','--cache',path.join(stage,'cache')],{env});}
fs.writeFileSync(path.join(stage,'first-install.log'),install());
assert.equal(commandVersion(),'mcpsense v'+pkg.version,'plain command must execute new npm runtime');
const backups=fs.readdirSync(goDir).filter(n=>n.includes('.mcpsense-backup-'));assert.equal(backups.length,1);
assert.deepEqual(fs.readFileSync(path.join(goDir,backups[0])),before);
assert.equal(fs.readFileSync(path.join(goDir,'unrelated-tool.txt'),'utf8'),'preserved');
fs.writeFileSync(path.join(stage,'repeat-install.log'),install());assert.equal(commandVersion(),'mcpsense v'+pkg.version);
assert.equal(fs.readdirSync(goDir).filter(n=>n.includes('.mcpsense-backup-')).length,1);
// Also exercise a genuinely fresh global installation, without any Go command.
const freshPrefix=path.join(stage,'fresh npm'),freshBin=process.platform==='win32'?freshPrefix:path.join(freshPrefix,'bin');
const freshEnv={...env,npm_config_prefix:freshPrefix,PATH:[freshBin,path.dirname(process.execPath),process.platform==='win32'?system:tools].join(path.delimiter)};
fs.writeFileSync(path.join(stage,'fresh-install.log'),run(process.execPath,[npm,'install','--global','--prefix',freshPrefix,tarball,'--foreground-scripts','--no-audit','--no-fund','--cache',path.join(stage,'cache')],{env:freshEnv}));
assert.equal(commandVersion(freshEnv),'mcpsense v'+pkg.version);
if(process.platform==='win32') {
  // Exercise the batch bridge with literal arguments and special characters in its target path.
  const special=path.join(stage,'arguments & percent % wow ! caret ^');fs.mkdirSync(special);
  const echo=path.join(special,'echo.js');fs.writeFileSync(echo,'console.log(JSON.stringify(process.argv.slice(2)))');
  const cmd=path.join(special,'bridge.cmd');fs.writeFileSync(cmd,bridge(echo));
  const output=run(path.join(system,'cmd.exe'),['/d','/s','/c','""%MCPSENSE_TEST_BRIDGE%" "space value" "percent% literal" "bang! literal" "& literal""'],{env:{...env,MCPSENSE_TEST_BRIDGE:cmd},windowsVerbatimArguments:true});
  assert.deepEqual(JSON.parse(output),['space value','percent% literal','bang! literal','& literal']);
}
const evidence={version:pkg.version,node:process.version,platform:process.platform,plainCommandBefore:'0.3.0',plainCommandAfter:pkg.version,
  oldBackupSHA256:createHash('sha256').update(before).digest('hex'),backup:backups[0],normalGlobalLifecycle:true,freshGlobalInstall:true,noGoDuringInstallation:true,repeatInstall:true,unrelatedToolPreserved:true,tarball,integrity:pack.integrity};
fs.writeFileSync(path.join(stage,'results.json'),JSON.stringify(evidence,null,2)+'\n');
console.log('PASS: ordinary global npm installation replaces old command precedence, preserves backup and survives repeat installation.');
console.log('Evidence: '+path.join(stage,'results.json'));
