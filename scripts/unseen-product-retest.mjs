// Diagnostic: preserve observed misses; enable enforcement explicitly for a fix candidate.
import fs from 'node:fs';
import path from 'node:path';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {spawnSync} from './cli-process.cjs';

const binary=process.env.MCPSENSE_TEST_BINARY;
assert.ok(binary,'MCPSENSE_TEST_BINARY required; use the actual installed CLI/engine');
const fixture='testdata/product-unseen-2026-10-26.json';
const bytes=fs.readFileSync(fixture),cases=JSON.parse(bytes);
const sha256=data=>createHash('sha256').update(data).digest('hex');
const root=path.resolve(process.env.MCPSENSE_UNSEEN_DIR||'bin/unseen-product-retest');
fs.mkdirSync(root,{recursive:true});
const workspace=fs.mkdtempSync(path.join(root,'User project with spaces-'));
fs.writeFileSync(path.join(workspace,'frozen-labels.json'),bytes);
fs.writeFileSync(path.join(workspace,'before-scan.json'),JSON.stringify({corpusSha256:sha256(bytes),binary},null,2));
const version=spawnSync(binary,['version'],{encoding:'utf8',timeout:30000,windowsHide:true});
assert.equal(version.error,undefined);assert.equal(version.status,0,version.stderr);
const observations=[];
for(const surface of ['tool-description','server-instructions'])for(const c of cases){
 const manifest={name:'records',version:'1.0.0',protocolVersion:'2025-11-25',auth:{type:'oauth2'},tools:[{name:'read_record',description:surface==='tool-description'?c.text:'Read one stored record by its identifier.',inputSchema:{type:'object',properties:{id:{type:'string',description:'Record identifier.',maxLength:128}},required:['id'],examples:[{id:'one'}]}}]};
 if(surface==='server-instructions')manifest.instructions=c.text;
 const file=path.join(workspace,c.id+'-'+surface+'.json');fs.writeFileSync(file,JSON.stringify(manifest));
 const r=spawnSync(binary,['scan',file,'--offline','--no-baseline','--format','json'],{encoding:'utf8',timeout:30000,maxBuffer:8<<20,windowsHide:true});
 assert.equal(r.error,undefined);assert.ok([0,1].includes(r.status),c.id+': '+r.stderr);
 const report=JSON.parse(r.stdout);fs.writeFileSync(file+'.report.json',r.stdout);
 const injection=report.findings.some(f=>f.id==='SEC-001');
 const outcome=c.hostile?(injection?'TP':'FN'):(injection?'FP':'TN');
 observations.push({id:c.id,surface,hostile:c.hostile,injection,security:report.findings.some(f=>f.id.startsWith('SEC-')),outcome,score:report.score,exit:r.status,rules:report.findings.map(f=>f.id)});
 console.log(outcome+' '+c.id+' '+surface);
}
assert.equal(sha256(fs.readFileSync(fixture)),sha256(bytes),'Labels changed during evaluation');
const counts=Object.fromEntries(['TP','FN','FP','TN'].map(k=>[k,observations.filter(r=>r.outcome===k).length]));
const result={version:version.stdout.trim(),corpusSha256:sha256(bytes),binary,counts,observations,limitation:'Small newly authored examples, not field accuracy. Default mode measures known failures; it does not enforce security acceptance.'};
fs.writeFileSync(path.join(workspace,'results.json'),JSON.stringify(result,null,2));
console.log(JSON.stringify({counts,workspace}));
if(process.env.MCPSENSE_UNSEEN_ENFORCE==='1')assert.equal(counts.FN+counts.FP,0,'Unseen hostile/benign cases failed');
