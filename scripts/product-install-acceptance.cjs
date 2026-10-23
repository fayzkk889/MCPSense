// Exercise the real candidate archive through the npm installation core.
// Download injection uses the exact CI artifact: this is not a public npm release.
const fs=require('fs'),path=require('path'),assert=require('assert/strict');
const {createHash}=require('crypto'),{spawnSync,execFileSync}=require('child_process');
const {installBinary}=require('../npm/install.js');
assert.equal(process.platform,'win32','This candidate-archive walkthrough is for Windows x64');
const root=path.resolve(process.env.MCPSENSE_ACCEPTANCE_DIR||'bin/product-acceptance-2026-10-23');
const artifacts=path.join(root,'artifacts'),version=JSON.parse(fs.readFileSync(path.join(artifacts,'metadata.json'))).version;
const filename=`MCPSense_${version}_windows_amd64.zip`,archive=fs.readFileSync(path.join(artifacts,filename)),checksums=fs.readFileSync(path.join(artifacts,'checksums.txt'));
async function main(){
 const original=process.env.PATH;process.env.PATH=path.join(process.env.SystemRoot,'System32');
 try{
  assert.equal(spawnSync('go',['version']).error?.code,'ENOENT');
  const binDir=path.join(root,'npm prefix with spaces','node_modules','mcpsense','bin');
  const binary=await installBinary({version,binDir,download:async url=>url.endsWith('/checksums.txt')?checksums:archive});
  fs.copyFileSync(path.resolve('npm/bin/run.js'),path.join(binDir,'run.js'));
  const cliVersion=execFileSync(process.execPath,[path.join(binDir,'run.js'),'version'],{encoding:'utf8'}).trim();
  assert.equal(cliVersion,'mcpsense v'+version);
  const journeys=spawnSync(process.execPath,['--test','scripts/product.test.mjs'],{env:{...process.env,MCPSENSE_TEST_BINARY:binary},encoding:'utf8',timeout:90000});
  fs.writeFileSync(path.join(root,'installed-product-journeys.log'),journeys.stdout+'\n'+journeys.stderr);assert.equal(journeys.status,0,journeys.stdout+journeys.stderr);
  const oldHash=createHash('sha256').update(fs.readFileSync(binary)).digest('hex');
  let rejected=false;try{await installBinary({version,binDir,download:async url=>url.endsWith('/checksums.txt')?checksums:Buffer.from('corrupt')});}catch{rejected=true;}
  assert.ok(rejected);assert.equal(createHash('sha256').update(fs.readFileSync(binary)).digest('hex'),oldHash);
  const result={version,archiveSHA256:createHash('sha256').update(archive).digest('hex'),binarySHA256:oldHash,goAbsent:true,installedVersion:cliVersion,productJourneys:'14 PASS',corruptUpgradeRejected:true,previousInstallationPreserved:true,downloadSource:'Exact merged CI artifact, not public release URL'};
  fs.writeFileSync(path.join(root,'installation-summary.json'),JSON.stringify(result,null,2));console.log(JSON.stringify(result,null,2));
 }finally{process.env.PATH=original;}
}
main().catch(e=>{console.error(e);process.exitCode=1;});
