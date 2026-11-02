#!/usr/bin/env node
function managesUpdate(args) {
  const command = args.find(a => !/^--no-update-check(?:=(?:true|false))?$/.test(a));
  return command === 'update' && !args.some(a => ['--plan-json','--help','-h'].includes(a));
}
function runCLI(args, runtime = require('./wasm.js').runWasm) {
  if (runtime === require('./wasm.js').runWasm && managesUpdate(args)) {
    return require('./manage.cjs').update(args);
  }
  return runtime(args);
}
module.exports = { runCLI, managesUpdate };
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
