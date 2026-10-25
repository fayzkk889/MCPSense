// Historical native archive installer regression. New npm delivery is tested
// separately in npm-wasm-smoke.cjs; this helper is not shipped in npm packages.
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
  // Linux runners may have /usr/bin/go, so exposing system directories does
  // not prove independence. Expose only the archive tools the installer uses.
  // Node and the installed CLI are invoked by absolute paths below.
  if(windows)process.env.PATH=path.join(process.env.SystemRoot,'System32');
  else{
   const tools=path.join(tmp,'archive-tools');fs.mkdirSync(tools);
   for(const name of ['tar','gzip']){
    const source=execFileSync('/bin/sh',['-c','command -v "$1"','lookup',name],{encoding:'utf8'}).trim();
    assert.ok(path.isAbsolute(source),'Archive utility must resolve to an absolute path');
    fs.symlinkSync(source,path.join(tools,name));
   }
   process.env.PATH=tools;
  }
  const go=spawnSync('go',['version'],{encoding:'utf8'});
  assert.ok(go.error&&go.error.code==='ENOENT','Go must actually be unavailable for this check');
  const binary=await installBinary({version,binDir,download:async url=>{
   assert.ok(url.startsWith('https://github.com/fayzkk889/MCPSense/releases/download/v'+version+'/'));
   if(url.endsWith('/checksums.txt'))return Buffer.from(`${sum}  ${filename}\n`);
   assert.ok(url.endsWith('/'+filename));return data;
  }});
  assert.equal(execFileSync(binary,['version'],{encoding:'utf8'}).trim(),'mcpsense v'+version);
  execFileSync(process.execPath,['--test','scripts/product.test.mjs'],{env:{...process.env,MCPSENSE_TEST_BINARY:binary},stdio:'inherit'});
  console.log('PASS: real archive installation, npm wrapper and all user journeys with Go absent from PATH');
 }finally{process.env.PATH=priorPath;fs.rmSync(tmp,{recursive:true,force:true,maxRetries:10,retryDelay:100});}
}
main().catch(err=>{console.error(err);process.exitCode=1;});
