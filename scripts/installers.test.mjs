import {test} from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,mkdirSync,writeFileSync,readFileSync,existsSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join,resolve} from 'node:path';
import {spawnSync,execFileSync} from 'node:child_process';
import {createHash} from 'node:crypto';

const windows=process.platform==='win32';
const ps=join(process.env.SystemRoot??'C:\\Windows','System32/WindowsPowerShell/v1.0/powershell.exe');
function powershell(body,dir,env={}){
 return spawnSync(ps,['-NoProfile','-NonInteractive','-Command',body],{encoding:'utf8',env:{...process.env,INSTALLER:resolve('install.ps1'),DESTINATION:join(dir,'install with spaces'),...env}});
}
test('Windows installer explains Go requirement without falling back to a download',{skip:!windows},()=>{
 const dir=mkdtempSync(join(tmpdir(),'mcpsense-install-'));
 try{const r=powershell('& $env:INSTALLER -NoPathUpdate -InstallDir $env:DESTINATION',dir,{PATH:dir});assert.equal(r.status,1);assert.match(r.stderr,/Go 1\.22 or newer is required/);assert.equal(existsSync(join(dir,'install with spaces/mcpsense.exe')),false);}finally{rmSync(dir,{recursive:true,force:true});}
});
test('Windows installer does not report success after a failed source build',{skip:!windows},()=>{
 const dir=mkdtempSync(join(tmpdir(),'mcpsense-install-'));
 try{const r=powershell('function go { $global:LASTEXITCODE=17 }; & $env:INSTALLER -Version 0.4.0 -NoPathUpdate -InstallDir $env:DESTINATION',dir);assert.equal(r.status,1);assert.match(r.stderr,/Source installation failed/);assert.doesNotMatch(r.stdout,/Installed:/);}finally{rmSync(dir,{recursive:true,force:true});}
});
test('Windows installer accepts a full commit and starts the exact installed binary',{skip:!windows||!process.env.MCPSENSE_TEST_BINARY},()=>{
 const dir=mkdtempSync(join(tmpdir(),'mcpsense-install-'));
 const ref='1234567890abcdef1234567890abcdef12345678';
 try{
 const r=powershell('function go { [IO.File]::WriteAllText($env:ARG_LOG,$args[1]); Copy-Item -LiteralPath $env:MCPSENSE_TEST_BINARY -Destination (Join-Path $env:GOBIN "mcpsense.exe"); $global:LASTEXITCODE=0 }; & $env:INSTALLER -Version $env:SOURCE_REF -NoPathUpdate -InstallDir $env:DESTINATION',dir,{SOURCE_REF:ref,ARG_LOG:join(dir,'args.txt')});
 assert.equal(r.status,0,r.stderr);assert.match(r.stdout,/Installed: mcpsense/);assert.match(r.stdout,/PATH was not changed/);assert.equal(readFileSync(join(dir,'args.txt'),'utf8').trim(),'github.com/fayzkk889/MCPSense/cmd/mcpsense@'+ref);
 }finally{rmSync(dir,{recursive:true,force:true});}
});

for(const scenario of ['valid','corrupt','ambiguous','missing','windows'])test('Archive installer: '+scenario,{skip:windows},()=>{
 const dir=mkdtempSync(join(tmpdir(),'mcpsense-archive-'));const tools=join(dir,'tools');const payload=join(dir,'payload');const dest=join(dir,'install with spaces');
 try{
 mkdirSync(tools);mkdirSync(payload);mkdirSync(dest);
 writeFileSync(join(dest,'mcpsense'),'previous installation');
 writeFileSync(join(payload,'mcpsense'),'#!/bin/sh\nprintf "mcpsense v0.4.0 fixture\\n"\n',{mode:0o755});
 execFileSync('tar',['-czf',join(dir,'archive.tar.gz'),'-C',payload,'mcpsense']);
 const sum=createHash('sha256').update(readFileSync(join(dir,'archive.tar.gz'))).digest('hex');
 const record=`${scenario==='corrupt'?'0'.repeat(64):sum}  MCPSense_0.4.0_linux_amd64.tar.gz\n`;
 writeFileSync(join(dir,'checksums.txt'),scenario==='missing'?'':record+(scenario==='ambiguous'?record:''));
 writeFileSync(join(tools,'uname'),'#!/bin/sh\nif [ "$1" = -s ]; then printf "%s\\n" "$TEST_OS"; else printf "x86_64\\n"; fi\n',{mode:0o755});
 writeFileSync(join(tools,'curl'),'#!/bin/sh\nwhile [ "$#" -gt 0 ]; do case "$1" in https:*) url=$1 ;; -o) shift; output=$1 ;; esac; shift; done\ncase "$url" in */checksums.txt) cp "$TEST_DATA/checksums.txt" "$output" ;; *.tar.gz) cp "$TEST_DATA/archive.tar.gz" "$output" ;; *) exit 19 ;; esac\n',{mode:0o755});
 const r=spawnSync('sh',[resolve('install.sh')],{encoding:'utf8',env:{...process.env,PATH:tools+':'+process.env.PATH,TEST_DATA:dir,TEST_OS:scenario==='windows'?'MINGW64_NT':'Linux',MCPSENSE_VERSION:'0.4.0',MCPSENSE_INSTALL_DIR:dest}});
 assert.equal(r.status,scenario==='valid'?0:1,r.stderr);
 if(scenario==='valid'){assert.match(execFileSync(join(dest,'mcpsense'),['version'],{encoding:'utf8'}),/v0.4.0 fixture/);}else{assert.equal(readFileSync(join(dest,'mcpsense'),'utf8'),'previous installation');}
 if(scenario==='windows')assert.match(r.stderr,/use install.ps1 with Go installed/);
 }finally{rmSync(dir,{recursive:true,force:true});}
});
