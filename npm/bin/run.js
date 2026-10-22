#!/usr/bin/env node
const fs = require("fs");
const path = require("path");
const { spawnSync } = require("child_process");

function runCLI(args, launch = spawnSync, binary = path.join(__dirname, "mcpsense" + (process.platform === "win32" ? ".exe" : ""))) {
  if (!fs.existsSync(binary)) {
    console.error("MCPSense binary missing. Reinstall the package or build from source.");
    return 2;
  }
  const result = launch(binary, args, { shell: false, stdio: "inherit" });
  if (result.error || result.signal || result.status === null) return 2;
  return result.status;
}
module.exports = { runCLI };
if (require.main === module) process.exitCode = runCLI(process.argv.slice(2));
