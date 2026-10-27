// Only public, non-prerelease semantic versions can replace the dated snapshot.
export function versionParts(value) {
  const match = /^v?(\d{1,4})\.(\d{1,4})\.(\d{1,4})$/.exec(String(value));
  return match ? match.slice(1).map(Number) : null;
}

export function compareVersions(a, b) {
  const left = versionParts(a), right = versionParts(b);
  if (!left || !right) throw new Error('Unsupported release version');
  for (let i = 0; i < 3; i++) if (left[i] !== right[i]) return Math.sign(left[i] - right[i]);
  return 0;
}

export function releaseState(npm, github) {
  if (!versionParts(npm?.version) || !versionParts(github?.tag_name) ||
      github.draft !== false || github.prerelease !== false) throw new Error('Unverified public release metadata');
  const npmVersion = npm.version.replace(/^v/, '');
  const githubVersion = github.tag_name.replace(/^v/, '');
  return { agrees: npmVersion === githubVersion, npmVersion, githubVersion };
}
