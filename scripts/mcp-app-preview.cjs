'use strict';
// Local synthetic host for manually checking the embedded MCP Apps view.
// No real configurations or reports are served.
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const result={structuredContent:{version:'preview',report:{coverage:{state:'completed',surfaces:['manifest'],baseline:'skipped',advisories:'skipped'},security_assessment:{state:'review_required',limitation:'Synthetic preview. No safety or authorization verdict is established.'},findings:[
  {id:'SEC-001',severity:'high',title:'Instruction override',description:'The selected metadata attempts to override the assistant instructions.',location:{file:'manifest.json',tool_name:'selected_record'},remediation:'Remove instructions that override the host policy, then rescan.'},
  {id:'QUAL-001',severity:'low',title:'Untrusted text: <img src="/unexpected" onerror="alert(1)">',description:'This synthetic markup must display as text.',location:{file:'manifest.json'},remediation:'Review the tool description and provide a clear, limited purpose.'}
]}},content:[{type:'text',text:'Synthetic preview only.'}]};
const host=`<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>MCPSense local app test</title><style>body{font:15px system-ui;margin:20px}button{padding:8px;margin:0 8px 12px 0}iframe{width:100%;height:850px;border:1px solid #bbb}</style><h1>MCPSense local test host</h1><p>Synthetic findings only. No real project data.</p><button id="complete">Completed scan</button><button id="empty">Zero findings</button><button id="error">Failed scan</button><button id="cancel">Cancel scan</button><p id="handshake">Waiting for app handshake</p><iframe title="MCPSense findings panel" src="/report"></iframe><script>
const frame=document.querySelector('iframe'),result=${JSON.stringify(result)};
const send=(method,params)=>frame.contentWindow.postMessage({jsonrpc:'2.0',method,params},location.origin);
window.addEventListener('message',event=>{
 if(event.source!==frame.contentWindow||event.origin!==location.origin)return;
 const q=event.data;
 if(q.method==='ui/initialize')frame.contentWindow.postMessage({jsonrpc:'2.0',id:q.id,result:{protocolVersion:'2026-01-26',hostInfo:{name:'MCPSense local test',version:'1'},hostCapabilities:{},hostContext:{theme:'light',displayMode:'inline'}}},location.origin);
 if(q.method==='ui/notifications/initialized'){document.getElementById('handshake').textContent='App handshake complete';send('ui/notifications/tool-result',result);}
});
document.getElementById('complete').onclick=()=>send('ui/notifications/tool-result',result);
document.getElementById('empty').onclick=()=>{const clean=JSON.parse(JSON.stringify(result));clean.structuredContent.report.findings=[];clean.structuredContent.report.security_assessment.state='not_established';send('ui/notifications/tool-result',clean);};
document.getElementById('error').onclick=()=>send('ui/notifications/tool-result',{isError:true,content:[{type:'text',text:'Selected input is unavailable. Inspection did not complete.'}]});
document.getElementById('cancel').onclick=()=>send('ui/notifications/tool-cancelled',{});
</script></html>`;
http.createServer((req,res)=>{
 res.setHeader('Content-Type','text/html; charset=utf-8');
 res.setHeader('Cache-Control','no-store');
 if(req.url==='/'){res.end(host);return;}
 if(req.url==='/report'){res.end(fs.readFileSync(path.join(__dirname,'../internal/mcpserver/report.html')));return;}
 res.statusCode=404;res.end('Not found');
}).listen(0,'127.0.0.1',function(){console.log('Local synthetic MCP Apps preview: http://127.0.0.1:'+this.address().port);});
