'use strict';
// Reuse unchanged product expectations for a checkout or installed npm runner.
const path = require('path');
const {spawnSync} = require('child_process');
const root = path.resolve(__dirname,'..');
const output = path.resolve(process.env.MCPSENSE_NPM_PRODUCT_DIR || 'bin/npm-product');
const env = {...process.env,
  MCPSENSE_TEST_BINARY:process.env.MCPSENSE_TEST_BINARY || path.join(root,'npm/runtime/mcpsense.wasm'),
  MCPSENSE_TEST_RUNNER:process.env.MCPSENSE_TEST_RUNNER || path.join(root,'npm/bin/run.js'),
  MCPSENSE_TEST_WASM:'1', MCPSENSE_VALIDATION:'1', MCPSENSE_INTENT_VALIDATION:'1', MCPSENSE_ENFORCE_PRODUCT:'1', MCPSENSE_FRESH_ENFORCE:'1',
  MCPSENSE_PERSONA_DIR:path.join(output,'persona'), MCPSENSE_BASELINE_DIR:path.join(output,'baseline'),
  MCPSENSE_THREAT_DIR:path.join(output,'threat'), MCPSENSE_DEPENDENCY_DIR:path.join(output,'dependency'), MCPSENSE_FRESH_DIR:path.join(output,'fresh')};
const commands = [
  ['--test','npm/runtime.test.cjs','internal/nodebridge/node.test.cjs','scripts/npm-stdio.test.cjs','scripts/product.test.mjs'],
  ['scripts/product-acceptance.mjs'],['scripts/persona-acceptance.mjs'],['scripts/product-live-acceptance.mjs'],
  ['scripts/baseline-acceptance.mjs'],['scripts/threat-review.mjs'],['scripts/dependency-acceptance.mjs'],['scripts/fresh-product-retest.mjs']];
for (const args of commands) {
  env.MCPSENSE_ACCEPTANCE_DIR=path.join(output,args.includes('scripts/product-live-acceptance.mjs')?'live':'core');
  const result=spawnSync(process.execPath,args,{cwd:root,env,stdio:'inherit',windowsHide:true,timeout:300000});
  if(result.error || result.status!==0) {console.error('npm product suite failed: '+args.join(' '));process.exit(result.status || 1);}
}
console.log('PASS: npm product suite completed with the same native CLI expectations.');
