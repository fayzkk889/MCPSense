export function vscodeInstallUrl(folder, version) {
  const root = folder.trim().replace(/[\\/]+$/, '');
  const absolute = /^(?:[A-Za-z]:[\\/]|\/(?!\/))/.test(root);
  const components = root.split(/[\\/]/);
  if (!absolute || components.some(part => part === '.' || part === '..') || /[\u0000-\u001f\u007f"&|<>^%!]|\$\{/.test(root)) {
    throw new Error('Enter the full path to a local project folder, such as C:\\dev\\my-project or /home/me/my-project. For other paths, use the terminal setup below.');
  }
  if (!/^\d+\.\d+\.\d+$/.test(version)) throw new Error('The VS Code installer version is unavailable. Use terminal setup below.');

  const configuration = {
    name: 'mcpsense',
    type: 'stdio',
    command: 'npx',
    // Keep npm package resolution outside the project being inspected.
    cwd: '${userHome}',
    args: ['--yes', '--ignore-scripts', '--registry=https://registry.npmjs.org/', `--package=mcpsense@${version}`, '--', 'mcpsense', 'mcp', 'serve', '--root', root],
  };
  return `vscode:mcp/install?${encodeURIComponent(JSON.stringify(configuration))}`;
}

export function setupVSCodeInstall(form) {
  const folder = form.querySelector('input');
  const status = form.querySelector('[role="status"]');
  form.addEventListener('submit', event => {
    event.preventDefault();
    try {
      const url = vscodeInstallUrl(folder.value, form.dataset.vscodeInstall);
      status.textContent = 'Approve opening VS Code, then review the MCPSense configuration in the editor.';
      window.location.href = url;
    } catch (error) {
      status.textContent = error.message;
      folder.focus();
    }
  });
  form.hidden = false;
}
