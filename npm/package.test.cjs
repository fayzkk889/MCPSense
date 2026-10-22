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
