const {test}=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const os=require('node:os');
const path=require('node:path');
const {createHash}=require('node:crypto');

test('declared executable is shipped and passes literal arguments',()=>{
 const pkg=require('./package.json');const wrapper=path.join(__dirname,pkg.bin.mcpsense);assert.ok(fs.existsSync(wrapper),'declared npm executable missing');
 const {runCLI}=require(wrapper);const tmp=fs.mkdtempSync(path.join(os.tmpdir(),'mcpsense-wrapper-'));
 try{
  const binary=path.join(tmp,'fake-binary');fs.writeFileSync(binary,'synthetic');const payload='x"; echo SENTINEL; #';
  const status=runCLI(['scan',payload],(file,args,opts)=>{assert.equal(file,binary);assert.deepEqual(args,['scan',payload]);assert.equal(opts.shell,false);return {status:2};},binary);
  assert.equal(status,2);
 }finally{fs.rmSync(tmp,{recursive:true,force:true})}
});
test('archive checksum rejects corruption and missing or ambiguous records',()=>{
 const {verifyArchive}=require('./install.js');const bytes=Buffer.from('synthetic');const digest=createHash('sha256').update(bytes).digest('hex');
 assert.doesNotThrow(()=>verifyArchive(bytes,`${digest}  archive.tar.gz\n`,'archive.tar.gz'));
 for(const manifest of ['bad',`${'0'.repeat(64)}  archive.tar.gz`,`${digest}  archive.tar.gz\n${digest}  archive.tar.gz`])assert.throws(()=>verifyArchive(bytes,manifest,'archive.tar.gz'));
});
test('wrapper starts the reviewed compiled CLI', {skip:!process.env.MCPSENSE_TEST_BINARY},()=>{
 const {runCLI}=require('./bin/run.js');
 assert.equal(runCLI(['--help'],undefined,process.env.MCPSENSE_TEST_BINARY),0);
});

test('release selection supports independent npm installs on all configured targets',()=>{
 const {getDownloadUrl}=require('./install.js');
 for(const [platform,architecture,filename] of [['win32','x64','windows_amd64.zip'],['linux','x64','linux_amd64.tar.gz'],['linux','arm64','linux_arm64.tar.gz'],['darwin','x64','darwin_amd64.tar.gz'],['darwin','arm64','darwin_arm64.tar.gz']])assert.ok(getDownloadUrl('0.4.0',platform,architecture).endsWith(filename));
 assert.throws(()=>getDownloadUrl('0.4.0','win32','arm64'),/No release binary/);
});

for(const platform of ['win32','linux','darwin'])test('npm installs '+platform+' without ever invoking Go',async()=>{
 const {installBinary,getDownloadUrl}=require('./install.js');const dir=fs.mkdtempSync(path.join(os.tmpdir(),'mcpsense-npm-'));
 const data=Buffer.from('synthetic reviewed archive'),filename=getDownloadUrl('0.4.0',platform,'x64').split('/').pop();
 const digest=createHash('sha256').update(data).digest('hex');const calls=[];let renames=0;
 try{
  const existing=path.join(dir,platform==='win32'?'mcpsense.exe':'mcpsense');fs.writeFileSync(existing,'previous binary');fs.writeFileSync(path.join(dir,'run.js'),'preserve wrapper');fs.writeFileSync(path.join(dir,'user-note.txt'),'preserve unrelated file');
  const binary=await installBinary({version:'0.4.0',binDir:dir,platform,architecture:'x64',rename:(from,to)=>{if(++renames===1&&platform==='win32')throw Object.assign(Error('temporarily locked'),{code:'EBUSY'});fs.renameSync(from,to);},download:async url=>url.endsWith('checksums.txt')?Buffer.from(`${digest}  ${filename}\n`):data,run:(file,args,opts)=>{
   calls.push(file);assert.notEqual(file,'go');assert.equal(opts.shell,false);
   if(file==='tar'){assert.equal(args[args.length-1],platform==='win32'?'mcpsense.exe':'mcpsense');fs.writeFileSync(path.join(args[3],args[4]),'new binary');return;}
   assert.deepEqual(args,['version']);return 'mcpsense v0.4.0\n';
  }});
  assert.equal(fs.readFileSync(binary,'utf8'),'new binary');assert.equal(fs.readFileSync(path.join(dir,'run.js'),'utf8'),'preserve wrapper');assert.equal(fs.readFileSync(path.join(dir,'user-note.txt'),'utf8'),'preserve unrelated file');assert.equal(calls.length,2);assert.equal(renames,platform==='win32'?2:1);
 }finally{fs.rmSync(dir,{recursive:true,force:true});}
});

test('npm rejects corrupt or mismatched binaries before replacing an installation',async()=>{
 const {installBinary}=require('./install.js');
 for(const failure of ['checksum','startup','version']){
  const dir=fs.mkdtempSync(path.join(os.tmpdir(),'mcpsense-npm-'));const existing=path.join(dir,'mcpsense.exe');fs.writeFileSync(existing,'previous binary');const data=Buffer.from('synthetic');const hash=createHash('sha256').update(data).digest('hex');let calls=0;
  try{
   await assert.rejects(installBinary({version:'0.4.0',binDir:dir,platform:'win32',architecture:'x64',download:async url=>url.endsWith('checksums.txt')?Buffer.from(`${failure==='checksum'?'0'.repeat(64):hash}  MCPSense_0.4.0_windows_amd64.zip\n`):data,run:(file,args)=>{calls++;if(file==='tar'){fs.writeFileSync(path.join(args[3],args[4]),'new binary');return;}if(failure==='startup')throw Error('blocked by platform');return 'mcpsense v0.3.0';}}));
   assert.equal(fs.readFileSync(existing,'utf8'),'previous binary');assert.equal(fs.readdirSync(dir).length,1);if(failure==='checksum')assert.equal(calls,0);
  }finally{fs.rmSync(dir,{recursive:true,force:true});}
 }
});

test('transient file locks retry with a bound and permanent failures are preserved',async()=>{
 const {retryFileOperation}=require('./install.js');
 for(const code of ['EBUSY','EPERM','EACCES']) {
  let calls=0;const delays=[];
  const result=await retryFileOperation(()=>{if(++calls<3)throw Object.assign(Error('locked'),{code});return 'installed';},{sleep:async ms=>delays.push(ms)});
  assert.equal(result,'installed');assert.equal(calls,3);assert.deepEqual(delays,[100,200]);
 }
 for(const code of ['EBUSY','EINVAL']) {
  let calls=0;const failure=Object.assign(Error('persistent'),{code});
  await assert.rejects(retryFileOperation(()=>{calls++;throw failure;},{sleep:async()=>{},maxRetries:2}),err=>err===failure);
  assert.equal(calls,code==='EBUSY'?3:1);
 }
});

test('locked replacement preserves the prior installation and cleanup does not hide startup errors',async()=>{
 const {installBinary}=require('./install.js');
 const data=Buffer.from('synthetic'),hash=createHash('sha256').update(data).digest('hex');
 for(const failure of ['replacement','startup']) {
  const dir=fs.mkdtempSync(path.join(os.tmpdir(),'mcpsense-npm-lock-'));
  const previous=path.join(dir,'mcpsense.exe');fs.writeFileSync(previous,'previous binary');
  const original=Object.assign(Error(failure==='startup'?'startup blocked':'replacement denied'),{code:'EINVAL'});
  try {
   await assert.rejects(installBinary({version:'0.4.0',binDir:dir,platform:'win32',architecture:'x64',
    download:async url=>url.endsWith('checksums.txt')?Buffer.from(`${hash}  MCPSense_0.4.0_windows_amd64.zip\n`):data,
    run:(file,args)=>{if(file==='tar'){fs.writeFileSync(path.join(args[3],args[4]),'new binary');return;}if(failure==='startup')throw original;return 'mcpsense v0.4.0';},
    rename:()=>{throw original;},
    remove:(file,options)=>{assert.equal(options.maxRetries,10);assert.equal(options.retryDelay,100);fs.rmSync(file,options);if(failure==='startup')throw Error('cleanup denied');}
   }),err=>err===original&&err.message.includes(failure==='startup'?'startup blocked':'replacement denied'));
   assert.equal(fs.readFileSync(previous,'utf8'),'previous binary');assert.deepEqual(fs.readdirSync(dir),['mcpsense.exe']);
   if(failure==='startup')assert.ok(original.message.includes('cleanup denied'));
  }finally{fs.rmSync(dir,{recursive:true,force:true,maxRetries:10,retryDelay:100});}
 }
});
