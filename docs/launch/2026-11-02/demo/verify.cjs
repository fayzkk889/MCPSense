'use strict';
// Inspect synthetic text only: no real credentials, network access or server execution.
const fs=require('node:fs'),path=require('node:path'),assert=require('node:assert/strict'),{spawnSync}=require('node:child_process');
const args=process.argv.slice(2),at=args.indexOf('--runner');
if(at<0||!args[at+1])throw Error('Pass --runner with the absolute path to the installed npm bin/run.js');
const runner=path.resolve(args[at+1]),fixtures=require('../../../../testdata/metadata-value-identity-2026-11-01.json');
const cases=['q7-flow-h','q7-flow-b','q7-definition-h','q7-definition-b'];
const output=path.resolve(process.env.MCPSENSE_LAUNCH_DEMO_DIR||'bin/launch-045-demo');fs.mkdirSync(output,{recursive:true});
const results=[];
for(const id of cases){
 const item=fixtures.find(c=>c.id===id);assert.ok(item);
 const manifest={name:'synthetic-launch-demo',version:'1.0.0',protocolVersion:'2025-11-25',auth:{type:'oauth2'},tools:[{name:'read_record',description:item.text,inputSchema:{type:'object',properties:{id:{type:'string',maxLength:128}},required:['id']}}]};
 const file=path.join(output,id+'.json');fs.writeFileSync(file,JSON.stringify(manifest,null,2)+'\n');
 const result=spawnSync(process.execPath,[runner,'scan',file,'--offline','--no-baseline','--checks','SEC-001,SEC-011','--format','json'],{encoding:'utf8',windowsHide:true,timeout:30000});
 assert.equal(result.status,item.hostile?1:0,result.stderr);const report=JSON.parse(result.stdout);
 const findings=report.findings.filter(f=>['SEC-001','SEC-011'].includes(f.id));
 assert.equal(findings.length>0,item.hostile,id);fs.writeFileSync(path.join(output,id+'.report.json'),result.stdout);
 results.push({id,description:item.text,hostile:item.hostile,exit:result.status,rules:[...new Set(findings.map(f=>f.id))]});
}
fs.writeFileSync(path.join(output,'results.json'),JSON.stringify({productVersion:'0.4.5',synthetic:true,offline:true,toolsCalled:0,scope:'SEC-001 and SEC-011 on four existing authored cases; not a Black October incident reproduction or field benchmark',results},null,2)+'\n');
console.log(JSON.stringify(results,null,2));
