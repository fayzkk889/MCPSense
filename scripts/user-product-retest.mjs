// Frozen user-labelled descriptions. Injection outcomes and other security
// review signals are separate; a benign directive can have an invalid hint.
import fs from 'node:fs';
import path from 'node:path';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {spawnSync} from './cli-process.cjs';
const binary=process.env.MCPSENSE_TEST_BINARY;
if(!binary)throw Error('MCPSENSE_TEST_BINARY required');
const root=path.resolve(process.env.MCPSENSE_USER_RETEST_DIR || 'bin/user-product-retest');fs.mkdirSync(root,{recursive:true});
const workspace=fs.mkdtempSync(path.join(root,'User project with spaces-'));
const bytes=fs.readFileSync('testdata/product-user-retest-2026-10-25.json'),cases=JSON.parse(bytes),observations=[];
const wsl=process.env.MCPSENSE_ACCEPTANCE_WSL;
const linuxPath=v=>v.replace(/^([A-Za-z]):[\\/]/,(_,d)=>'/mnt/'+d.toLowerCase()+'/').replaceAll('\\','/');
for(const surface of ['tool-description','server-instructions'])for(const c of cases){
 const manifest={name:'records',version:'1.0.0',protocolVersion:'2025-11-25',auth:{type:'oauth2'},tools:[{name:'read_record',description:surface==='tool-description'?c.text:'Return the selected record.',inputSchema:{type:'object',properties:{id:{type:'string',description:'Record identifier.',maxLength:128}},required:['id'],examples:[{id:'one'}]},annotations:{readOnlyHint:c.readOnly??true}}]};
 if(surface==='server-instructions')manifest.instructions=c.text;
 const file=path.join(workspace,c.id+'-'+surface+'.json');fs.writeFileSync(file,JSON.stringify(manifest));
 const args=['scan',file,'--offline','--no-baseline','--format','json'];
 const r=spawnSync(wsl?'wsl':binary,wsl?['-d',wsl,'--',linuxPath(binary),...args.map(a=>/^[A-Za-z]:[\\/]/.test(a)?linuxPath(a):a)]:args,{encoding:'utf8',timeout:30000,maxBuffer:8<<20,windowsHide:true});
 assert.equal(r.error,undefined);assert.ok([0,1].includes(r.status),c.id+': '+r.stderr);
 const report=JSON.parse(r.stdout),detected=report.findings.some(f=>f.id==='SEC-001');
 const outcome=c.hostile?(detected?'TP':'FN'):(detected?'FP':'TN');
 const row={id:c.id,hostile:c.hostile,surface,outcome,exit:r.status,score:report.score,rules:report.findings.map(f=>f.id)};observations.push(row);
 fs.writeFileSync(path.join(workspace,c.id+'-'+surface+'-report.json'),JSON.stringify(report,null,2));console.log(outcome+' '+c.id+' '+surface+' '+row.rules.join(','));
}
const counts=Object.fromEntries(['TP','FN','FP','TN'].map(k=>[k,observations.filter(r=>r.outcome===k).length]));
const result={corpusSha256:createHash('sha256').update(bytes).digest('hex'),binary,counts,observations};
fs.writeFileSync(path.join(workspace,'results.json'),JSON.stringify(result,null,2));console.log(JSON.stringify({counts,workspace}));
if(process.env.MCPSENSE_USER_RETEST_ENFORCE==='1')assert.equal(counts.FN+counts.FP,0,'User-labelled injection cases failed');
