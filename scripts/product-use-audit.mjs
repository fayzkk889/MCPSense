// Evaluate frozen user intent through an existing CLI; never execute fixture directives.
import fs from 'node:fs';
import path from 'node:path';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {spawnSync} from './cli-process.cjs';

const binary=process.env.MCPSENSE_TEST_BINARY;
assert.ok(binary,'Point MCPSENSE_TEST_BINARY at the existing product');
const fixture='testdata/product-use-audit-2026-10-31.json';
const frozen=fs.readFileSync(fixture),cases=JSON.parse(frozen);
const hash=bytes=>createHash('sha256').update(bytes).digest('hex');
const root=path.resolve(process.env.MCPSENSE_USE_AUDIT_DIR||'bin/product-use-audit-2026-10-31');
fs.mkdirSync(root,{recursive:true});
const workspace=fs.mkdtempSync(path.join(root,'User project with spaces-'));
fs.writeFileSync(path.join(workspace,'frozen-labels.json'),frozen);
const observations=[];
const version=spawnSync(binary,['version'],{encoding:'utf8',timeout:45000,windowsHide:true});
assert.equal(version.error,undefined);assert.equal(version.status,0,version.stderr);
for(const surface of ['tool-description','server-instructions','schema-description'])for(const c of cases){
 const manifest={name:'records',version:'1.0.0',protocolVersion:'2025-11-25',auth:{type:'oauth2'},tools:[{name:'read_record',description:'Read a stored record by its identifier.',inputSchema:{type:'object',properties:{id:{type:'string',description:'Record identifier.',maxLength:128}},required:['id'],examples:[{id:'one'}]}}]};
 if(surface==='tool-description')manifest.tools[0].description=c.text;
 if(surface==='server-instructions')manifest.instructions=c.text;
 if(surface==='schema-description')manifest.tools[0].inputSchema.properties.id.description=c.text;
 const file=path.join(workspace,c.id+'-'+surface+'.json');
 fs.writeFileSync(file,JSON.stringify(manifest));
 const r=spawnSync(binary,['scan',file,'--offline','--no-baseline','--format','json'],{encoding:'utf8',timeout:45000,maxBuffer:8<<20,windowsHide:true});
 assert.equal(r.error,undefined,c.id);assert.ok([0,1].includes(r.status),c.id+': '+r.stderr);
 fs.writeFileSync(file+'.report.json',r.stdout);
 const report=JSON.parse(r.stdout);
 assert.equal(report.coverage.state,'completed');
 assert.equal(report.security_assessment.authorization_enforced,false);
 const findings=report.findings.filter(f=>f.id.startsWith('SEC-'));
 const detected=findings.length>0;
 const outcome=c.hostile?(detected?'TP':'FN'):(detected?'FP':'TN');
 observations.push({id:c.id,surface,hostile:c.hostile,reason:c.reason,text:c.text,outcome,exit:r.status,score:report.score,securityAssessment:report.security_assessment,findings:findings.map(f=>({id:f.id,severity:f.severity,title:f.title,description:f.description,location:f.location})),allRules:report.findings.map(f=>f.id)});
 console.log(outcome+' '+c.id+' '+surface);
}
assert.equal(hash(fs.readFileSync(fixture)),hash(frozen),'Frozen labels changed');
const counts=Object.fromEntries(['TP','FN','FP','TN'].map(k=>[k,observations.filter(o=>o.outcome===k).length]));
const distinct=cases.map(c=>({...c,outcomes:observations.filter(o=>o.id===c.id).map(o=>({surface:o.surface,outcome:o.outcome,exit:o.exit,rules:o.allRules}))}));
const result={version:version.stdout.trim(),binary,corpusSha256:hash(frozen),workspace,counts,observations,distinct,acceptancePassed:counts.FN+counts.FP===0,limitation:'48 newly authored descriptions, repeated across three supported metadata fields. This is targeted product testing, not independent field accuracy or runtime enforcement.'};
fs.writeFileSync(path.join(workspace,'results.json'),JSON.stringify(result,null,2));
console.log(JSON.stringify({workspace,counts,acceptancePassed:result.acceptancePassed}));
// Preserve every result before failing strict product acceptance.
process.exitCode=result.acceptancePassed?0:1;
