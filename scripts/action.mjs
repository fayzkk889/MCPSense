import {appendFileSync, chmodSync, existsSync, mkdtempSync, readFileSync, writeFileSync} from 'node:fs';
import {tmpdir, platform, arch} from 'node:os';
import {join, resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {spawnSync} from 'node:child_process';
import {createHash} from 'node:crypto';

const ranks={info:0,low:1,medium:2,high:3,critical:4};
const enumValue=(value,allowed,name)=>{if(!allowed.includes(value))throw Error(`Invalid ${name}`);return value;};
const boolean=(value,name)=>enumValue(value??'false',['true','false'],name)==='true';
export function parseInputs(env){
 const version=env.VERSION??'source';
 if(!['source','latest'].includes(version)&&!/^v?\d+\.\d+\.\d+(?:-[a-zA-Z0-9.-]+)?$/.test(version))throw Error('Invalid version');
 if(!env.TARGET)throw Error('Target required');
 return {target:env.TARGET,version,mode:enumValue(env.MODE??'auto',['auto','static','manifest','config','skill','live'],'mode'),severity:enumValue(env.SEVERITY??'low',Object.keys(ranks),'severity'),failOn:enumValue(env.FAIL_ON??'high',[...Object.keys(ranks),'none'],'fail-on'),offline:boolean(env.OFFLINE??'true','offline'),noCVE:boolean(env.NO_CVE,'no-cve'),sarif:boolean(env.SARIF_UPLOAD??'true','sarif-upload'),baseline:env.BASELINE??''};
}
export function validateReport(r){
 if(r?.schema_version!==2||r.coverage?.state!=='completed'||!Array.isArray(r.coverage.surfaces)||r.coverage.surfaces.length===0||!['completed','skipped','not_applicable'].includes(r.coverage.advisories)||!Number.isInteger(r.score)||r.score<0||r.score>100||!Array.isArray(r.findings)||r.summary?.total!==r.findings.length)throw Error('Missing, unsupported or incomplete scan result');
 for(const f of r.findings)if(!f||typeof f.id!=='string'||!Object.hasOwn(ranks,f.severity))throw Error('Invalid finding');
 return r;
}
export function exceedsThreshold(r,threshold){return threshold!=='none'&&r.findings.some(f=>ranks[f.severity]>=ranks[threshold]);}
export function runScan(binary,opts,dir,launch=spawnSync){
 const jsonFile=join(dir,'results.json'),sarifFile=join(dir,'results.sarif');
 // A fresh private directory prevents reuse of stale output from previous steps.
 if(existsSync(jsonFile)||existsSync(sarifFile))throw Error('Output paths must be fresh');
 const args=['scan','--mode',opts.mode,'--severity',opts.severity,'--format','json','--output',jsonFile];
 if(opts.offline)args.push('--offline');if(opts.noCVE)args.push('--no-cve');
 if(opts.baseline)args.push('--baseline',opts.baseline);else args.push('--no-baseline');
 args.push('--sarif-output',sarifFile);
 args.push('--',opts.target);
 const child=launch(binary,args,{shell:false,stdio:'inherit',timeout:120000});
 if(child.error||child.signal||![0,1].includes(child.status))throw Error('Scanner execution failed');
 const report=validateReport(JSON.parse(readFileSync(jsonFile,'utf8')));
 const expected=report.findings.some(f=>ranks[f.severity]>=ranks.high)?1:0;
 if(child.status!==expected)throw Error('Scanner exit status contradicts report');
 {
  const sarif=JSON.parse(readFileSync(sarifFile,'utf8'));
  if(sarif.version!=='2.1.0'||sarif.runs?.length!==1||!Array.isArray(sarif.runs[0].results)||sarif.runs[0].results.length!==report.findings.length)throw Error('Invalid SARIF result');
  for(let i=0;i<report.findings.length;i++)if(sarif.runs[0].results[i].ruleId!==report.findings[i].id)throw Error('JSON/SARIF finding mismatch');
 }
 return {report,jsonFile,sarifFile};
}
async function download(url,limit){
 for(let hop=0;hop<=5;hop++){
  const u=new URL(url);
  if(u.protocol!=='https:'||!['github.com','api.github.com','release-assets.githubusercontent.com','objects.githubusercontent.com'].includes(u.hostname)||u.username||u.password)throw Error('Disallowed download URL');
  const r=await fetch(u,{redirect:'manual',signal:AbortSignal.timeout(30000),headers:{'User-Agent':'MCPSense-action'}});
  if([301,302,303,307,308].includes(r.status)){const loc=r.headers.get('location');await r.body?.cancel();if(!loc)throw Error('Missing redirect');url=new URL(loc,u).href;continue;}
  if(!r.ok)throw Error(`Release download failed (${r.status})`);
  const parts=[];let bytes=0;
  for await(const chunk of r.body){bytes+=chunk.length;if(bytes>limit)throw Error('Download exceeds size limit');parts.push(chunk);}
  return Buffer.concat(parts);
 }
 throw Error('Too many download redirects');
}
async function acquire(opts,dir){
 const ext=platform()==='win32'?'.exe':'';const binary=join(dir,'mcpsense'+ext);
 if(opts.version==='source'){
  const root=resolve(process.env.GITHUB_ACTION_PATH??fileURLToPath(new URL('..',import.meta.url)));
  const build=spawnSync('go',['build','-trimpath','-o',binary,'./cmd/mcpsense'],{cwd:root,shell:false,stdio:'inherit',timeout:180000});
  if(build.error||build.status!==0)throw Error('Building trusted Action source failed');return binary;
 }
 let version=opts.version;
 if(version==='latest')version=JSON.parse((await download('https://api.github.com/repos/fayzkk889/MCPSense/releases/latest',1<<20)).toString()).tag_name;
 if(typeof version!=='string'||!/^v?\d+\.\d+\.\d+(?:-[a-zA-Z0-9.-]+)?$/.test(version))throw Error('Invalid release version');
 version=version.replace(/^v/,'');
 const os={win32:'windows',linux:'linux',darwin:'darwin'}[platform()];const cpu={x64:'amd64',arm64:'arm64'}[arch()];
 if(!os||!cpu)throw Error('Unsupported runner');
 const archive=`MCPSense_${version}_${os}_${cpu}.${os==='windows'?'zip':'tar.gz'}`;
 const base=`https://github.com/fayzkk889/MCPSense/releases/download/v${version}/`;
 const checksums=(await download(base+'checksums.txt',1<<20)).toString();
 const entries=checksums.split(/\r?\n/).map(l=>l.trim().split(/\s+/)).filter(x=>x.length===2&&x[1]===archive);
 if(entries.length!==1||!/^[a-fA-F0-9]{64}$/.test(entries[0][0]))throw Error('Missing or ambiguous archive checksum');
 const data=await download(base+archive,64<<20);
 if(createHash('sha256').update(data).digest('hex')!==entries[0][0].toLowerCase())throw Error('Release checksum mismatch');
 const archivePath=join(dir,archive);writeFileSync(archivePath,data);
 const extract=spawnSync('tar',['-xf',archivePath,'-C',dir,'mcpsense'+ext],{shell:false,stdio:'inherit',timeout:30000});
 if(extract.error||extract.status!==0||!existsSync(binary))throw Error('Binary extraction failed');
 chmodSync(binary,0o755);return binary;
}
async function main(){
 const opts=parseInputs(process.env);const dir=mkdtempSync(join(process.env.RUNNER_TEMP??tmpdir(),'mcpsense-'));
 const binary=await acquire(opts,dir);const result=runScan(binary,opts,dir);
 if(!process.env.GITHUB_OUTPUT)throw Error('GITHUB_OUTPUT missing');
 appendFileSync(process.env.GITHUB_OUTPUT,`score=${result.report.score}\nfindings_count=${result.report.summary.total}\nsarif_file=${result.sarifFile}\nthreshold_failed=${exceedsThreshold(result.report,opts.failOn)}\n`);
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url))main().catch(()=>{console.error('::error::MCPSense execution or result validation failed. Review preceding scanner/build diagnostics.');process.exitCode=1;});
