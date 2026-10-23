package main

import (
	"fmt"
	"github.com/spf13/cobra"
	"os"
)

const exampleManifest = `{
  "name": "example_records", "version": "1.0.0", "protocolVersion": "2025-11-25",
  "auth": {"type":"oauth2"},
  "tools": [{"name":"read_record","description":"Retrieve one selected record by identifier and return its display name.",
    "inputSchema":{"type":"object","properties":{"record_id":{"type":"string","description":"The identifier of the selected record.","maxLength":128}},"required":["record_id"]}}]
}
`

func writeExample(cmd *cobra.Command) error {
	file, err := os.OpenFile("mcp.json", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return fmt.Errorf("cannot create example mcp.json (existing files are preserved): %w", err)
	}
	if _, err := file.WriteString(exampleManifest); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	fmt.Fprintln(cmd.OutOrStdout(), "Created mcp.json with synthetic example metadata. It does not run a server or connect any client.")
	fmt.Fprintln(cmd.OutOrStdout(), "Next: mcpsense scan ./mcp.json --offline --no-baseline")
	fmt.Fprintln(cmd.OutOrStdout(), "For your real setup, pass the path to its existing MCP configuration instead of this example.")
	return nil
}
