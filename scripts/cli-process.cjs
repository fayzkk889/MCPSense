'use strict';
// Test adapter: run the exact same journeys against a native CLI or the Node
// entrypoint. All arguments stay literal; this never uses a shell.
const child = require('child_process');
const {promisify} = require('util');
const path = require('path');
function command(file, args) {
  if (process.env.MCPSENSE_TEST_RUNNER && file === process.env.MCPSENSE_TEST_BINARY) {
    return [process.execPath, [path.resolve(process.env.MCPSENSE_TEST_RUNNER), ...args]];
  }
  return [file, args];
}
function spawnSync(file, args, options) {const [exe, argv] = command(file, args); return child.spawnSync(exe, argv, options);}
function execFile(file, args, ...rest) {const [exe, argv] = command(file, args); return child.execFile(exe, argv, ...rest);}
execFile[promisify.custom] = (file, args, options) => {const [exe, argv] = command(file, args); return child.execFile[promisify.custom](exe, argv, options);};
module.exports = {spawnSync, execFile};
