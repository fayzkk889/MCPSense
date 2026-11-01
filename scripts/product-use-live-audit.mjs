// A harmless loopback MCP peer advertises frozen descriptions. No tool executes.
import fs from 'node:fs';
import path from 'node:path';
import http from 'node:http';
import assert from 'node:assert/strict';
import {promisify} from 'node:util';
import {execFile} from './cli-process.cjs';
const exec=promisify(execFile),binary=process.env.MCPSENSE_TEST_BINARY;
assert.ok(binary,'Use the existing released product');
const cases=JSON.parse(fs.readFileSync('testdata/product-use-audit-2026-10-31.json','utf8'));
const root=path.resolve(process.env.MCPSENSE_USE_LIVE_DIR||'bin/product-use-live-2026-10-31');
fs.mkdirSync(root,{recursive:true});
const calls=[],observations=[];
let current,surface;
const peer=http.createServer(async(req,res)=>{
 let body='';for await(const chunk of req)body+=chunk;
 const q=JSON.parse(body);calls.push({case:current.id,surface,method:q.method});
 const tool={name:'read_record',description:surface==='tool-description'?current.text:'Read a stored record by its identifier.',inputSchema:{type:'object',properties:{id:{type:'string',description:'Record identifier.'}},required:['id']}};
 let result;
 if(q.method==='server/discover')result={resultType:'complete',supportedVersions:['2026-07-28'],capabilities:{tools:{}},instructions:surface==='server-instructions'?current.text:undefined,_meta:{'io.modelcontextprotocol/serverInfo':{name:'frozen-product-audit',version:'1'}}};
 else if(q.method==='tools/list')result={resultType:'complete',tools:[tool]};
 else {res.writeHead(500).end();return;}
 res.writeHead(200,{'Content-Type':'application/json'}).end(JSON.stringify({jsonrpc:'2.0',id:q.id,result}));
});
await new Promise(resolve=>peer.listen(0,'127.0.0.1',resolve));
const target='http://127.0.0.1:'+peer.address().port+'/mcp';
try{
 for(surface of ['tool-description','server-instructions'])for(const id of ['credential-env-h','cookie-relay-h','monitor-queue-h','tls-identity-b','credential-redacted-b','approved-data-b']){
  current=cases.find(c=>c.id===id);let r;
  try{const value=await exec(binary,['scan',target,'--allow-private-network','--no-cve','--no-baseline','--format','json'],{encoding:'utf8',windowsHide:true,timeout:45000,maxBuffer:8<<20});r={exit:0,...value};}
  catch(error){r={exit:error.code,stdout:error.stdout||'',stderr:error.stderr||''};}
  assert.ok([0,1].includes(r.exit),current.id+': '+r.stderr);
  const report=JSON.parse(r.stdout);assert.equal(report.coverage.state,'completed');
  const findings=report.findings.filter(f=>f.id.startsWith('SEC-'));
  const outcome=current.hostile?(findings.length?'TP':'FN'):(findings.length?'FP':'TN');
  observations.push({id,surface,hostile:current.hostile,outcome,exit:r.exit,score:report.score,rules:findings.map(f=>f.id)});
  fs.writeFileSync(path.join(root,id+'-'+surface+'.json'),JSON.stringify({...r,report},null,2));
  console.log(outcome+' '+id+' '+surface);
 }
 assert.ok(calls.every(q=>['server/discover','tools/list'].includes(q.method)),'Unexpected active tool call');
}finally{await new Promise(resolve=>peer.close(resolve));}
const counts=Object.fromEntries(['TP','FN','FP','TN'].map(k=>[k,observations.filter(o=>o.outcome===k).length]));
fs.writeFileSync(path.join(root,'results.json'),JSON.stringify({observations,counts,calls,noToolsCalled:true},null,2));
console.log(JSON.stringify({counts,noToolsCalled:true}));
process.exitCode=counts.FN+counts.FP?1:0;
