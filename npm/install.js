const os = require("os");
const fs = require("fs");
const path = require("path");
const https = require("https");
const { execFileSync } = require("child_process");
const { createHash } = require("crypto");

const REPO = "fayzkk889/MCPSense";
const BINARY_NAME = "mcpsense";

// Map Node.js os values to GoReleaser naming
const PLATFORM_MAP = {
  darwin: "darwin",
  linux: "linux",
  win32: "windows",
};

const ARCH_MAP = {
  x64: "amd64",
  arm64: "arm64",
};

function getPackageVersion() {
  const pkg = JSON.parse(
    fs.readFileSync(path.join(__dirname, "package.json"), "utf8")
  );
  return pkg.version;
}

function getBinaryPath() {
  const binDir = path.join(__dirname, "bin");
  const ext = os.platform() === "win32" ? ".exe" : "";
  return path.join(binDir, BINARY_NAME + ext);
}

function getDownloadUrl(version) {
  const platform = PLATFORM_MAP[os.platform()];
  const arch = ARCH_MAP[os.arch()];

  if (!platform) {
    throw new Error(
      `Unsupported platform: ${os.platform()}. MCPSense supports darwin, linux, and win32.`
    );
  }
  if (!arch) {
    throw new Error(
      `Unsupported architecture: ${os.arch()}. MCPSense supports x64 and arm64.`
    );
  }

  // IMPORTANT: Adjust this pattern to match your actual GoReleaser output names.
  // Read .goreleaser.yml to confirm. The tag is "v" + version.
  const tag = `v${version}`;
  const ext = platform === "windows" ? "zip" : "tar.gz";
  const archiveName = `MCPSense_${version}_${platform}_${arch}.${ext}`;

  return `https://github.com/${REPO}/releases/download/${tag}/${archiveName}`;
}

function downloadFile(url) {
  return new Promise((resolve, reject) => {
    const follow = (url, redirects = 0) => {
	  const parsed = new URL(url);
	  if (parsed.protocol !== "https:" || !["github.com", "release-assets.githubusercontent.com", "objects.githubusercontent.com"].includes(parsed.hostname) || parsed.username || parsed.password) return reject(new Error("Disallowed download URL"));
      if (redirects > 5) {
        return reject(new Error("Too many redirects"));
      }

      https
        .get(url, { headers: { "User-Agent": "mcpsense-npm" } }, (res) => {
          // Follow redirects (GitHub releases redirect to S3)
          if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
            const redirectUrl = new URL(res.headers.location, url).href;
            res.resume();
            return follow(redirectUrl, redirects + 1);
          }

          if (res.statusCode !== 200) {
            return reject(
              new Error(`Download failed: HTTP ${res.statusCode} from ${url}`)
            );
          }

          const chunks = [];
          let size = 0;
          res.on("data", (chunk) => { size += chunk.length; if (size > 64 * 1024 * 1024) { res.destroy(new Error("Download exceeds size limit")); return; } chunks.push(chunk); });
          res.on("end", () => resolve(Buffer.concat(chunks)));
          res.on("error", reject);
        })
        .on("error", reject).setTimeout(30000, function () { this.destroy(new Error("Download timed out")); });
    };

    follow(url);
  });
}

function extractTarGz(buffer, destDir) {
  // Write to temp file, extract with tar
  const tmpFile = path.join(destDir, "download.tar.gz");
  fs.writeFileSync(tmpFile, buffer);

  try {
    execFileSync("tar", ["-xzf", tmpFile, "-C", destDir, BINARY_NAME], { stdio: "pipe", shell: false });
  } finally {
    // Clean up the archive
    try {
      fs.unlinkSync(tmpFile);
    } catch (_) {}
  }
}

function extractZip(buffer, destDir) {
  // Write to temp file, extract with PowerShell
  const tmpFile = path.join(destDir, "download.zip");
  fs.writeFileSync(tmpFile, buffer);

  try {
    if (os.platform() === "win32") {
      execFileSync("tar", ["-xf", tmpFile, "-C", destDir, BINARY_NAME + ".exe"], { stdio: "pipe", shell: false });
    } else {
      execFileSync("unzip", ["-o", tmpFile, BINARY_NAME, "-d", destDir], { stdio: "pipe", shell: false });
    }
  } finally {
    try {
      fs.unlinkSync(tmpFile);
    } catch (_) {}
  }
}

function installFromSource(binaryPath) {
  console.log("Windows detected — compiling MCPSense from its Go source...");

  // Check if Go is available
  try {
    execFileSync("go", ["version"], { stdio: "pipe", shell: false });
  } catch (_) {
    console.error("");
    console.error("mcpsense requires Go 1.22 or newer on Windows.");
    console.error("Windows installation compiles from source; Node.js alone is not sufficient.");
    console.error("");
    console.error("Install Go from https://go.dev/dl/ then retry:");
    console.error("  npm install -g mcpsense");
    console.error("");
    console.error("On Linux/macOS, Go is not required.");
    process.exit(1);
  }

  const version = getPackageVersion();
  const goPackage = `github.com/fayzkk889/MCPSense/cmd/mcpsense@v${version}`;

  console.log(`Running: go install ${goPackage}`);
	const binDir = path.dirname(binaryPath);
	fs.mkdirSync(binDir, { recursive: true });

  try {
    execFileSync("go", ["install", goPackage], { stdio: "inherit", shell: false, env: { ...process.env, GOBIN: binDir } });
  } catch (err) {
    console.error(`\ngo install failed: ${err.message}`);
    console.error(`\nTry manually:`);
    console.error("  go install github.com/fayzkk889/MCPSense/cmd/mcpsense@latest");
    process.exit(1);
  }

  // Explicit GOBIN installs directly into the package's binary directory.
  const goBinary = binaryPath;

  if (!fs.existsSync(goBinary)) {
    console.error(`Binary not found at ${goBinary} after go install.`);
    process.exit(1);
  }

  if (!fs.existsSync(binDir)) {
    fs.mkdirSync(binDir, { recursive: true });
  }

  console.log("mcpsense installed successfully (compiled from source).");
}

async function main() {
  const binaryPath = getBinaryPath();

  // Skip if binary already exists (e.g., reinstall)
  if (fs.existsSync(binaryPath)) {
    console.log(`mcpsense binary already exists at ${binaryPath}`);
    return;
  }

  // On Windows, compile from source to avoid Defender false positives
  if (os.platform() === "win32") {
    return installFromSource(binaryPath);
  }

  const version = getPackageVersion();
  const url = getDownloadUrl(version);

  console.log(`Downloading mcpsense v${version} for ${os.platform()}/${os.arch()}...`);
  console.log(`URL: ${url}`);

  try {
    const data = await downloadFile(url);
    const checksums = await downloadFile(url.substring(0, url.lastIndexOf("/") + 1) + "checksums.txt");
    verifyArchive(data, checksums.toString("utf8"), url.substring(url.lastIndexOf("/") + 1));
    const binDir = path.join(__dirname, "bin");

    // Ensure bin directory exists
    if (!fs.existsSync(binDir)) {
      fs.mkdirSync(binDir, { recursive: true });
    }

    // Extract based on archive type
    if (os.platform() === "win32") {
      extractZip(data, binDir);
    } else {
      extractTarGz(data, binDir);
    }

    // After extraction, the binary might be at bin/mcpsense or bin/MCPSense_*/mcpsense
    // depending on GoReleaser config. Find it.
    const ext = os.platform() === "win32" ? ".exe" : "";
    const expectedBinary = BINARY_NAME + ext;

    // Check if binary is directly in bin/
    if (!fs.existsSync(binaryPath)) {
      // Search one level deep for the binary
      const entries = fs.readdirSync(binDir, { withFileTypes: true });
      for (const entry of entries) {
        if (entry.isDirectory()) {
          const nestedPath = path.join(binDir, entry.name, expectedBinary);
          if (fs.existsSync(nestedPath)) {
            fs.renameSync(nestedPath, binaryPath);
            // Clean up the extracted directory
            fs.rmSync(path.join(binDir, entry.name), { recursive: true, force: true });
            break;
          }
        }
        // Also check if GoReleaser used a different case
        if (entry.isFile() && entry.name.toLowerCase() === expectedBinary.toLowerCase() && entry.name !== expectedBinary) {
          fs.renameSync(path.join(binDir, entry.name), binaryPath);
          break;
        }
      }
    }

    if (!fs.existsSync(binaryPath)) {
      throw new Error(
        `Binary not found after extraction. Expected at ${binaryPath}. Contents of bin/: ${fs.readdirSync(binDir).join(", ")}`
      );
    }

    // Make executable on Unix
    if (os.platform() !== "win32") {
      fs.chmodSync(binaryPath, 0o755);
    }

    console.log(`mcpsense v${version} installed successfully.`);

    // Clean up extra files from GoReleaser archive (LICENSE, README, etc.)
    const keepFiles = new Set([expectedBinary, "run.js", ".gitkeep"]);
    for (const file of fs.readdirSync(binDir)) {
      if (!keepFiles.has(file)) {
        try {
          const fullPath = path.join(binDir, file);
          const stat = fs.statSync(fullPath);
          if (stat.isDirectory()) {
            fs.rmSync(fullPath, { recursive: true, force: true });
          } else {
            fs.unlinkSync(fullPath);
          }
        } catch (_) {}
      }
    }
  } catch (err) {
    console.error(`\nFailed to install mcpsense: ${err.message}`);
    console.error(`\nFallback: install manually with Go:`);
    console.error(`  go install github.com/fayzkk889/MCPSense/cmd/mcpsense@latest`);
    console.error(`\nOr download from: https://github.com/${REPO}/releases`);
    process.exit(1);
  }
}

function verifyArchive(data, manifest, filename) {
  const records = manifest.split(/\r?\n/).map(line => line.trim().split(/\s+/)).filter(parts => parts.length === 2 && parts[1] === filename);
  if (records.length !== 1 || !/^[a-fA-F0-9]{64}$/.test(records[0][0]) || createHash("sha256").update(data).digest("hex") !== records[0][0].toLowerCase()) throw new Error("Release checksum verification failed");
}

module.exports = { verifyArchive, getDownloadUrl };
if (require.main === module) main();
