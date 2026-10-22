import {test} from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync, writeFileSync, rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {parseInputs, runScan, validateReport, exceedsThreshold} from './action.mjs';

const report = () => ({schema_version:2,score:75,coverage:{state:'completed',surfaces:['manifest'],advisories:'skipped'},summary:{total:1},findings:[{id:'SEC-001',severity:'high'}]});
test('inputs reject malformed enums, boolean values and version injection',()=>{
 for(const env of [{MODE:'bad'},{FAIL_ON:'anything'},{OFFLINE:'yes'},{VERSION:'1.0.0;echo bad'}]) assert.throws(()=>parseInputs({TARGET:'fixture.json',...env}));
});
test('formatted JSON is validated structurally and high threshold works',()=>{
 const r=validateReport(JSON.parse(JSON.stringify(report(),null,2)));
 assert.equal(exceedsThreshold(r,'high'),true);assert.equal(exceedsThreshold(r,'critical'),false);assert.equal(exceedsThreshold(r,'none'),false);
});
test('missing/inconsistent/partial reports fail',()=>{
 for(const r of [{}, {...report(),score:NaN},{...report(),summary:{total:0}},{...report(),coverage:{state:'failed'}},{...report(),findings:[{severity:'unknown'}]}])assert.throws(()=>validateReport(r));
});
test('shell metacharacters stay literal and exactly one scan supplies JSON and SARIF',()=>{
 const dir=mkdtempSync(join(tmpdir(),'mcpsense-action-'));try{
  const payload='x"; echo SYNTHETIC_SENTINEL; # $(echo harmless)';let calls=0;
  const opts=parseInputs({TARGET:payload,BASELINE:payload,OFFLINE:'true',SARIF_UPLOAD:'true'});
  const result=runScan('scanner',opts,dir,(file,args,options)=>{
   calls++;assert.equal(file,'scanner');assert.equal(options.shell,false);assert.equal(args.at(-1),payload);
   assert.equal(args[args.indexOf('--baseline')+1],payload);assert.ok(args.includes('--sarif-output'));
   writeFileSync(args[args.indexOf('--output')+1],JSON.stringify(report(),null,2));
   writeFileSync(args[args.indexOf('--sarif-output')+1],JSON.stringify({version:'2.1.0',runs:[{results:[{ruleId:'SEC-001'}]}]}));
   return {status:1};
  });assert.equal(calls,1);assert.equal(result.report.summary.total,1);
 }finally{rmSync(dir,{recursive:true,force:true})}
});
test('fail-on none cannot hide crashes, missing output or malformed JSON',()=>{
 for(const variant of ['crash','missing','malformed','false-success']){
  const dir=mkdtempSync(join(tmpdir(),'mcpsense-action-'));try{
   const opts=parseInputs({TARGET:'fixture.json',FAIL_ON:'none',SARIF_UPLOAD:'false'});
   assert.throws(()=>runScan('scanner',opts,dir,(file,args)=>{
    if(variant==='malformed')writeFileSync(args[args.indexOf('--output')+1],'{');
    if(variant==='crash')return {status:2};
    if(variant==='false-success')writeFileSync(args[args.indexOf('--output')+1],JSON.stringify(report()));
    return {status:0};
   }));
  }finally{rmSync(dir,{recursive:true,force:true})}
 }
});
