'use strict';
// Original failures, frozen validation and the fresh incident-inspired audit gate
// native and installed npm products. No diagnostic exit-0 mode in this suite.
const path=require('node:path'),{spawnSync}=require('node:child_process');
for(const [name,fixture] of [['original','product-unseen-2026-10-26.json'],['validation','boundary-validation-2026-10-26.json'],['incident-audit','product-black-october-2026-10-27.json'],['effects','product-effects-2026-10-28.json']]){
 const env={...process.env,MCPSENSE_UNSEEN_ENFORCE:'1',MCPSENSE_EXPECT_ASSESSMENT:'1',MCPSENSE_UNSEEN_FIXTURE:path.join('testdata',fixture),MCPSENSE_UNSEEN_DIR:path.join(process.env.MCPSENSE_BOUNDARY_DIR||'bin/boundary-acceptance',name)};
 const result=spawnSync(process.execPath,['scripts/unseen-product-retest.mjs'],{env,stdio:'inherit',windowsHide:true,timeout:240000});
 if(result.error||result.status!==0){console.error('Boundary acceptance failed: '+name);process.exit(result.status||1);}
}
console.log('PASS: 232 frozen trust-boundary observations, strict native/npm acceptance.');
const gate=spawnSync(process.execPath,['scripts/metadata-gate-acceptance.mjs'],{env:process.env,stdio:'inherit',windowsHide:true,timeout:120000});
if(gate.error||gate.status!==0)process.exit(gate.status||1);
for(const [name,fixture] of [['user-audit','product-use-audit-2026-10-31.json'],['trust-validation','metadata-trust-validation-2026-11-01.json'],['trust-fresh','metadata-trust-fresh-2026-11-01.json'],['trust-user-check','metadata-trust-user-check-2026-11-01.json']]){
 const env={...process.env,MCPSENSE_USE_AUDIT_FIXTURE:path.join('testdata',fixture),MCPSENSE_USE_AUDIT_DIR:path.join(process.env.MCPSENSE_BOUNDARY_DIR||'bin/boundary-acceptance',name)};
 const result=spawnSync(process.execPath,['scripts/product-use-audit.mjs'],{env,stdio:'inherit',windowsHide:true,timeout:240000});
 if(result.error||result.status!==0){console.error('Fresh metadata acceptance failed: '+name);process.exit(result.status||1);}
}
console.log('PASS: 366 additional observations in three metadata fields; frozen labels unchanged.');
const live=spawnSync(process.execPath,['scripts/product-use-live-audit.mjs'],{env:{...process.env,MCPSENSE_USE_LIVE_DIR:path.join(process.env.MCPSENSE_BOUNDARY_DIR||'bin/boundary-acceptance','trust-live')},stdio:'inherit',windowsHide:true,timeout:120000});
if(live.error||live.status!==0)process.exit(live.status||1);
