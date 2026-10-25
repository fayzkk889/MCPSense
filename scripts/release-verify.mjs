// Read-only release gate. Never publishes, tags, installs, or runs downloaded code.
import fs from 'node:fs';
import {createHash} from 'node:crypto';
import {execFileSync} from 'node:child_process';
import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
const pkg=JSON.parse(fs.readFileSync('npm/package.json','utf8'));
assert.match(pkg.version,/^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/);
assert.equal(pkg.license,'MIT');assert.equal(fs.readFileSync('LICENSE','utf8'),fs.readFileSync('npm/LICENSE','utf8'));
const head=execFileSync('git',['rev-parse','HEAD'],{encoding:'utf8'}).trim();
if(process.env.GITHUB_REF?.startsWith('refs/tags/'))assert.equal(process.env.GITHUB_REF,'refs/tags/v'+pkg.version,'Tag and npm package version differ');
const archives=['windows_amd64.zip','linux_amd64.tar.gz','linux_arm64.tar.gz','darwin_amd64.tar.gz','darwin_arm64.tar.gz'].map(target=>`MCPSense_${pkg.version}_${target}`);
const allowed=new Set(['api.github.com','github.com','registry.npmjs.org','release-assets.githubusercontent.com','objects.githubusercontent.com']);
async function download(address,limit,depth=0){
 const url=new URL(address);assert.ok(url.protocol==='https:'&&allowed.has(url.hostname)&&!url.username&&!url.password&&depth<=5,'Untrusted release URL');
 const response=await fetch(url,{redirect:'manual',signal:AbortSignal.timeout(30000),headers:{'User-Agent':'mcpsense-release-verification'}});
 if(response.status>=300&&response.status<400&&response.headers.has('location')){await response.body?.cancel();return download(new URL(response.headers.get('location'),url).href,limit,depth+1);}
 assert.equal(response.status,200,'Release lookup/download failed');let size=0;const chunks=[];
 for await(const chunk of response.body){size+=chunk.length;if(size>limit){await response.body?.cancel().catch(()=>{});throw Error('Release response exceeds limit');}chunks.push(chunk);}
 return Buffer.concat(chunks);
}
async function main(){
 console.log(`Candidate ${pkg.version}, commit ${head}: package metadata and MIT license agree.`);
 if(process.argv.includes('--npm')) {
  assert.equal(pkg.scripts?.install,undefined);assert.equal(pkg.scripts?.postinstall,undefined);assert.equal(pkg.scripts?.preinstall,undefined);
  assert.equal(pkg.engines.node,'>=22');assert.ok(!pkg.files.includes('install.js'));
  createRequire(import.meta.url)('../npm/bin/wasm.js').verifyRuntime('npm/runtime',pkg.version);
  console.log('Bundled npm engine, Go runtime license and component checksums verified; no installation hooks.');
 }
 if(!process.argv.includes('--public')){console.log('Public availability NOT checked. Use --public after approved publication; code push alone does not update npm/Go releases.');return;}
 const release=JSON.parse(await download('https://api.github.com/repos/fayzkk889/MCPSense/releases/latest',2<<20));
 const npm=JSON.parse(await download('https://registry.npmjs.org/mcpsense/latest',1<<20));
 assert.equal(release.tag_name,'v'+pkg.version,'GitHub latest does not deliver the candidate');assert.equal(npm.version,pkg.version,'npm latest does not deliver the candidate');assert.ok(!release.draft&&!release.prerelease);
 const manifest=await download(`https://github.com/fayzkk889/MCPSense/releases/download/v${pkg.version}/checksums.txt`,65536);
 for(const name of archives){assert.equal(release.assets.filter(a=>a.name===name).length,1,'Missing/ambiguous platform archive');const records=manifest.toString('utf8').split(/\r?\n/).map(line=>line.trim().split(/\s+/)).filter(parts=>parts.length===2&&parts[1]===name);assert.equal(records.length,1);assert.match(records[0][0],/^[0-9a-fA-F]{64}$/);const bytes=await download(`https://github.com/fayzkk889/MCPSense/releases/download/v${pkg.version}/${name}`,64<<20);assert.equal(createHash('sha256').update(bytes).digest('hex'),records[0][0].toLowerCase());console.log('Verified '+name);}
 const tag=execFileSync('git',['rev-list','-n','1','v'+pkg.version],{encoding:'utf8'}).trim();assert.equal(tag,head,'Local candidate is not the released tag');
 console.log('PASS: candidate tag, GitHub latest, npm latest, five archives and checksums agree. Public installation/startup still requires separate product tests.');
}
main().catch(error=>{console.error('Release gate FAILED: '+error.message);process.exitCode=1;});
