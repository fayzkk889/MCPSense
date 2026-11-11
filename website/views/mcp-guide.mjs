export function mcpGuide({command, product}) {
  return `<section id="mcp"><h2>03 / Connect your coding assistant</h2>
    <div id="vscode">
      <h3>Open in VS Code</h3>
      <p>Open a local project in desktop VS Code. With Node.js 22+ and npm available, enter that project’s full folder path to review the MCPSense configuration in VS Code.</p>
      <form class="vscode-install" data-vscode-install="${product.stable}" hidden>
        <label for="vscode-project">Project folder</label>
        <input id="vscode-project" type="text" required maxlength="4096" autocomplete="off" spellcheck="false" aria-describedby="vscode-install-note">
        <button class="button primary" type="submit">Add to VS Code</button>
        <p class="vscode-status" role="status"></p>
      </form>
      <p id="vscode-install-note">The path goes directly to VS Code. First start downloads npm version ${product.stable}. Scanning is offline and read-only by default. This link sets up an editor-managed MCP connection. For the native Copilot harness or shared CLI updates, use terminal setup below.</p>
    </div>
    <h3>Set up from the terminal</h3>
    <p>Requires <strong>MCPSense 0.5.0 or newer</strong>. Install with either route above, then check <code>mcpsense version</code>. The CLI and MCP tools come in the same package; there is no second server to install.</p>
    <p>Open the project directory you want to inspect. For Cursor:</p>
    ${command('mcpsense mcp install --client cursor --root .','Copy Cursor MCP setup command')}
    <p>Replace <code>cursor</code> with <code>vscode</code>, <code>copilot</code>, <code>claude-code</code>, <code>claude-desktop</code> or <code>codex</code> for your client. Existing settings and MCP server entries are preserved. JSONC configurations that need manual editing receive explicit instructions. Restart the client’s MCP connection after setup.</p>
    <h3>Ask for one real inspection</h3>
    <blockquote>Use MCPSense to scan this project’s MCP configuration offline. Explain the findings, what was inspected, and what remains unassessed.</blockquote>
    <p>Use an actual file or directory you selected inside the approved project. Ask for <code>mcpsense_status</code> to confirm the running version and permissions. The assistant can inspect supported metadata, configurations, source and skill files, explicitly selected npm lockfiles, and equivalent saved reports.</p>
    <h3>Permissions start small</h3>
    <p>The default server is <strong>offline and read-only</strong>, scoped to the selected root. It does not start commands found in inspected configurations or silently accept baselines. Optional network, executable startup and file-writing grants must be explicitly enabled at setup and requested by the operation. A reviewed baseline also requires human approval. A running assistant or authorized child process is not an OS sandbox.</p>
    <p>Clients that support MCP Apps can display an optional findings panel. Other clients receive the same structured report and readable findings.</p>
    <h3>Update once for both interfaces</h3>
    ${command('mcpsense update\nmcpsense version','Copy shared CLI and MCP update commands')}
    <p>Restart the client’s MCP connection to load the installed update. The client configuration continues to use the same installed command. A running connection does not silently replace its engine.</p>
    <p><a href="${product.github}/blob/main/docs/mcp.md">Full client, permission and generic stdio setup guide →</a></p>
  </section>`;
}
