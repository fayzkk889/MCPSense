## MCPSense 0.5.1

- MCP scans include all five severities by default. The findings panel shows the minimum severity when a scan requests a cutoff.
- Project setup supports OpenCode 1.x and its V2 configuration format. The same scanner also works with the existing Claude Code, Codex, VS Code, Cursor, and Copilot setups.
- The website can open the MCPSense setup in VS Code. A guided offline scan shows a high-severity finding and the change that clears it.
- Repositories can use a report-only GitHub Actions template to review changes to `.vscode/mcp.json`.
- The npm package carries the ownership identifier needed for the official MCP Registry listing.

[Setup guide](https://mcpsense.site/docs/#mcp) · [First scan walkthrough](https://mcpsense.site/blog/first-mcp-scan-in-your-assistant/)
