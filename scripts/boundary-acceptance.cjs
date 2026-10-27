'use strict';
// Original failures, frozen validation and the fresh incident-inspired audit gate
// native and installed npm products. No diagnostic exit-0 mode in this suite.
const path=require('node:path'),{spawnSync}=require('node:child_process');
for(const [name,fixture] of [['original','product-unseen-2026-10-26.json'],['validation','boundary-validation-2026-10-26.json'],['incident-audit','product-black-october-2026-10-27.json']]){
 const env={...process.env,MCPSENSE_UNSEEN_ENFORCE:'1',MCPSENSE_EXPECT_ASSESSMENT:'1',MCPSENSE_UNSEEN_FIXTURE:path.join('testdata',fixture),MCPSENSE_UNSEEN_DIR:path.join(process.env.MCPSENSE_BOUNDARY_DIR||'bin/boundary-acceptance',name)};
 const result=spawnSync(process.execPath,['scripts/unseen-product-retest.mjs'],{env,stdio:'inherit',windowsHide:true,timeout:240000});
 if(result.error||result.status!==0){console.error('Boundary acceptance failed: '+name);process.exit(result.status||1);}
}
console.log('PASS: 168 frozen trust-boundary observations, strict native/npm acceptance.');
const gate=spawnSync(process.execPath,['scripts/metadata-gate-acceptance.mjs'],{env:process.env,stdio:'inherit',windowsHide:true,timeout:120000});
if(gate.error||gate.status!==0)process.exit(gate.status||1);
