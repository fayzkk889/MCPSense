const os = require('os');
const fs = require('fs');
const path = require('path');
const https = require('https');
const {execFileSync} = require('child_process');
const {createHash} = require('crypto');

const REPO = 'fayzkk889/MCPSense';
const platforms = {darwin:'darwin',linux:'linux',win32:'windows'};
const architectures = {x64:'amd64',arm64:'arm64'};

function getDownloadUrl(version, platform=os.platform(), architecture=os.arch()) {
  const targetOS=platforms[platform], cpu=architectures[architecture];
  if (!targetOS || !cpu || (platform==='win32' && architecture==='arm64')) throw Error('No release binary for this platform/architecture. Supported: Windows x64; Linux/macOS x64 and arm64.');
  if (!/^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/.test(version)) throw Error('Invalid release version');
  return `https://github.com/${REPO}/releases/download/v${version}/MCPSense_${version}_${targetOS}_${cpu}.${platform==='win32'?'zip':'tar.gz'}`;
}

function downloadFile(url) {
  return new Promise((resolve,reject)=>{
    const follow=(address,redirects=0)=>{
      let parsed;
      try { parsed=new URL(address); } catch { reject(Error('Invalid download URL')); return; }
      if (parsed.protocol!=='https:' || !['github.com','release-assets.githubusercontent.com','objects.githubusercontent.com'].includes(parsed.hostname) || parsed.username || parsed.password || redirects>5) { reject(Error('Disallowed download URL or too many redirects')); return; }
      const req=https.get(parsed,{headers:{'User-Agent':'mcpsense-npm'}},res=>{
        res.on('error',reject);
        res.on('aborted',()=>reject(Error('Release download ended before completion')));
        if (res.statusCode>=300 && res.statusCode<400 && res.headers.location) {
          res.resume();
          try { follow(new URL(res.headers.location,parsed).href,redirects+1); } catch (err) { reject(err); }
          return;
        }
        if (res.statusCode!==200) { res.resume(); reject(Error(`Release download failed: HTTP ${res.statusCode}`)); return; }
        const chunks=[];let size=0;
        res.on('data',chunk=>{size+=chunk.length;if(size>64*1024*1024){res.destroy(Error('Download exceeds size limit'));return;}chunks.push(chunk);});
        res.on('end',()=>resolve(Buffer.concat(chunks)));
      });
      req.on('error',reject);
      // A total deadline also bounds peers that send one byte per idle timeout.
      const timer=setTimeout(()=>req.destroy(Error('Download timed out')),30000);
      req.on('close',()=>clearTimeout(timer));
    };
    follow(url);
  });
}

function verifyArchive(data,manifest,filename) {
  const records=manifest.split(/\r?\n/).map(line=>line.trim().split(/\s+/)).filter(parts=>parts.length===2 && parts[1]===filename);
  if (records.length!==1 || !/^[a-fA-F0-9]{64}$/.test(records[0][0]) || createHash('sha256').update(data).digest('hex')!==records[0][0].toLowerCase()) throw Error('Release checksum verification failed');
}

// Antivirus/indexing can briefly hold a verified executable after startup on
// Windows. Retry the same atomic rename; never delete the previous executable.
async function retryFileOperation(operation,{sleep=ms=>new Promise(resolve=>setTimeout(resolve,ms)),maxRetries=8}={}) {
  for(let attempt=0;;attempt++) {
    try { return operation(); } catch(err) {
      if(!['EBUSY','EPERM','EACCES'].includes(err.code) || attempt>=maxRetries) throw err;
      await sleep(100*(attempt+1));
    }
  }
}

async function installBinary({version,binDir,platform=os.platform(),architecture=os.arch(),download=downloadFile,run=execFileSync,rename=fs.renameSync,remove=fs.rmSync}) {
  const url=getDownloadUrl(version,platform,architecture);
  const filename=url.slice(url.lastIndexOf('/')+1);
  const base=url.slice(0,url.lastIndexOf('/')+1);
  const data=await download(url);
  const checksums=await download(base+'checksums.txt');
  verifyArchive(data,checksums.toString('utf8'),filename);
  fs.mkdirSync(binDir,{recursive:true});
  const stage=fs.mkdtempSync(path.join(binDir,'.install-'));
  const name='mcpsense'+(platform==='win32'?'.exe':'');
  const binary=path.join(stage,name);
  let installError;
  try {
    const archive=path.join(stage,filename);fs.writeFileSync(archive,data);
    run('tar',['-xf',archive,'-C',stage,name],{shell:false,stdio:'pipe',timeout:30000,windowsHide:true});
    if (!fs.lstatSync(binary).isFile()) throw Error('Archive did not contain a regular CLI executable');
    if (platform!=='win32') fs.chmodSync(binary,0o755);
    // Check startup before replacing an existing installation. No Go invocation.
    const actual=run(binary,['version'],{shell:false,encoding:'utf8',stdio:'pipe',timeout:15000,windowsHide:true});
    if (String(actual).trim()!==`mcpsense v${version}`) throw Error('Downloaded CLI version does not match the npm package');
    const destination=path.join(binDir,name);
    await retryFileOperation(()=>rename(binary,destination));
    return destination;
  } catch(err) {
    installError=err;
    throw err;
  } finally {
    try {
      remove(stage,{recursive:true,force:true,maxRetries:10,retryDelay:100});
    } catch(cleanupError) {
      // Preserve the actual startup/integrity/replacement failure for support.
      if(!installError) throw cleanupError;
      installError.message+=` (temporary installation cleanup failed: ${cleanupError.message})`;
    }
  }
}

async function main() {
  const version=JSON.parse(fs.readFileSync(path.join(__dirname,'package.json'),'utf8')).version;
  console.log(`Installing mcpsense v${version} for ${os.platform()}/${os.arch()} (Go is not required)...`);
  const binary=await installBinary({version,binDir:path.join(__dirname,'bin')});
  console.log(`mcpsense v${version} installed successfully: ${binary}`);
}

module.exports={verifyArchive,getDownloadUrl,installBinary,retryFileOperation};
if (require.main===module) main().catch(err=>{
  console.error(`Failed to install mcpsense: ${err.message}`);
  console.error('No Go compiler is required by this installer. Check release availability, network access, and operating-system protection history.');
  process.exitCode=1;
});
