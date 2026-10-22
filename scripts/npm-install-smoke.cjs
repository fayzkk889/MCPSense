// Exercise the production archive installer and wrapper with Go absent from PATH.
const fs=require('fs'),os=require('os'),path=require('path'),assert=require('assert/strict');
const {execFileSync,spawnSync}=require('child_process');
const {createHash}=require('crypto');
const {installBinary,getDownloadUrl}=require('../npm/install.js');

async function main(){
 assert.ok(process.env.MCPSENSE_TEST_BINARY,'MCPSENSE_TEST_BINARY is required');
 const tmp=fs.mkdtempSync(path.join(os.tmpdir(),'mcpsense-npm-real-'));
 const priorPath=process.env.PATH;
 try{
  const windows=process.platform==='win32',name=windows?'mcpsense.exe':'mcpsense';
  const payload=path.join(tmp,'payload');fs.mkdirSync(payload);
  fs.copyFileSync(process.env.MCPSENSE_TEST_BINARY,path.join(payload,name));
  if(!windows)fs.chmodSync(path.join(payload,name),0o755);
  const version=execFileSync(path.join(payload,name),['version'],{encoding:'utf8'}).trim().replace(/^mcpsense v/,'');
  const filename=getDownloadUrl(version).split('/').pop(),archive=path.join(tmp,filename);
  if(windows){
   execFileSync(path.join(process.env.SystemRoot,'System32/WindowsPowerShell/v1.0/powershell.exe'),['-NoProfile','-NonInteractive','-Command','Compress-Archive -LiteralPath $env:ARCHIVE_BINARY -DestinationPath $env:ARCHIVE_PATH'],{env:{...process.env,ARCHIVE_BINARY:path.join(payload,name),ARCHIVE_PATH:archive},windowsHide:true});
  }else execFileSync('tar',['-czf',archive,'-C',payload,name]);
  const data=fs.readFileSync(archive),sum=createHash('sha256').update(data).digest('hex');
  const binDir=path.join(tmp,'npm package with spaces','bin');
  // Use only system utilities. Node is invoked by its absolute path below.
  process.env.PATH=windows?path.join(process.env.SystemRoot,'System32'):'/usr/bin:/bin';
  const go=spawnSync('go',['version'],{encoding:'utf8'});
  assert.ok(go.error&&go.error.code==='ENOENT','Go must actually be unavailable for this check');
  const binary=await installBinary({version,binDir,download:async url=>{
   assert.ok(url.startsWith('https://github.com/fayzkk889/MCPSense/releases/download/v'+version+'/'));
   if(url.endsWith('/checksums.txt'))return Buffer.from(`${sum}  ${filename}\n`);
   assert.ok(url.endsWith('/'+filename));return data;
  }});
  fs.copyFileSync(path.resolve('npm/bin/run.js'),path.join(binDir,'run.js'));
  assert.equal(execFileSync(process.execPath,[path.join(binDir,'run.js'),'version'],{encoding:'utf8'}).trim(),'mcpsense v'+version);
  execFileSync(process.execPath,['--test','scripts/product.test.mjs'],{env:{...process.env,MCPSENSE_TEST_BINARY:binary},stdio:'inherit'});
  console.log('PASS: real archive installation, npm wrapper and all user journeys with Go absent from PATH');
 }finally{process.env.PATH=priorPath;fs.rmSync(tmp,{recursive:true,force:true});}
}
main().catch(err=>{console.error(err);process.exitCode=1;});
