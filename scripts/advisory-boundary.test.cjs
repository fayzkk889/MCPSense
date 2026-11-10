'use strict';
const {test}=require('node:test'),assert=require('node:assert/strict');
const fs=require('node:fs'),path=require('node:path'),os=require('node:os'),{createHash}=require('node:crypto');
const {spawnSync}=require('./cli-process.cjs');
const binary=process.env.MCPSENSE_TEST_BINARY;

test('A successful empty feed cannot erase reviewed AWS advisory evidence',{skip:!binary,timeout:60000},t=>{
  const root=fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(),'mcpsense-advisory-')));
  t.after(()=>fs.rmSync(root,{recursive:true,force:true}));
  const cache=path.join(root,'.mcpsense','cve-cache');fs.mkdirSync(cache,{recursive:true});
  for(const [name,id,cases] of [
    ['awslabs.aws-api-mcp-server','GHSA-4prq-p2x5-w9fh',[['1.2.9',false,false],['1.3.0',true,false],['1.5.0',true,false],['1.6.0',false,false],['1.6.0rc1',true,true],['',true,true]]],
    ['awslabs.aws-serverless-mcp-server','GHSA-r6mm-377j-qg8m',[['0.2.0',true,false],['0.2.1',false,false],['0.2.1rc1',true,true],['',true,true]]],
  ])for(const [version,want,candidate] of cases){
    const key=createHash('sha256').update('PyPI|'+name+'|'+version).digest('hex')+'.json';
    fs.writeFileSync(path.join(cache,key),JSON.stringify({cache_version:2,fetched_at:new Date().toISOString(),vulns:[]}));
    const config=path.join(root,'client.json');
    fs.writeFileSync(config,JSON.stringify({mcpServers:{api:{command:'uvx',args:['--from',name+(version?'=='+version:''),name]}}}));
    const response=spawnSync(binary,['scan',config,'--checks=CVE-001','--no-baseline','--format=json'],{cwd:root,env:{...process.env,HOME:root,USERPROFILE:root,MCPSENSE_NO_UPDATE_CHECK:'1'},encoding:'utf8',windowsHide:true,timeout:30000});
    assert.equal(response.status,want&&name==='awslabs.aws-api-mcp-server'?1:0,response.stderr+response.stdout);
    const report=JSON.parse(response.stdout);assert.equal(report.coverage.advisories,'completed');
    const matches=report.findings.filter(f=>f.advisory?.id===id);assert.equal(matches.length,want?1:0,version);
    if(want){
      assert.equal(matches[0].advisory.applicability,candidate?'version_unresolved':'reported_affected');
      assert.equal(matches[0].advisory.feed_url,'https://github.com/awslabs/mcp/security/advisories/'+id);
      assert.match(matches[0].description,/Deployment prerequisites were not assessed/);
      assert.match(matches[0].description,name==='awslabs.aws-api-mcp-server'?/AUTH_AUDIENCE/:/--enable-write/);
      assert.equal(report.security_assessment.authorization_enforced,false);
    }
    const disabled=spawnSync(binary,['scan',config,'--checks=CVE-001','--offline','--no-baseline','--format=json'],{cwd:root,env:{...process.env,HOME:root,USERPROFILE:root,MCPSENSE_NO_UPDATE_CHECK:'1'},encoding:'utf8',windowsHide:true,timeout:30000});
    assert.equal(disabled.status,0,disabled.stderr);assert.equal(JSON.parse(disabled.stdout).coverage.advisories,'skipped');
  }
});
