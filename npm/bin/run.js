#!/usr/bin/env node
function runCLI(args, runtime = require('./wasm.js').runWasm) {
  if (runtime === require('./wasm.js').runWasm && args[0] === 'update' && !args.some(a => ['--plan-json','--help','-h','--check','--check=true'].includes(a))) {
    return require('./manage.cjs').update(args);
  }
  return runtime(args);
}
module.exports = { runCLI };
if (require.main === module) {
  if (Number(process.versions.node.split('.')[0]) < 22) {
    console.error('MCPSense requires Node.js 22 or newer. Update Node.js, then retry.');
    process.exitCode = 2;
  } else {
    runCLI(process.argv.slice(2)).then(
      status => { process.exit(status); },
      error => { console.error('MCPSense runtime failed: ' + error.message); process.exit(2); }
    );
  }
}
