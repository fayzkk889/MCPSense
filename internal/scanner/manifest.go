package scanner

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/fayzkk889/MCPSense/internal/checks"
	"github.com/fayzkk889/MCPSense/internal/models"
)

// scanManifest loads and parses an MCP manifest JSON file into the scan context.
func (s *Scanner) scanManifest(target string, ctx *checks.ScanContext) error {
	data, err := os.ReadFile(target)
	if err != nil {
		return fmt.Errorf("reading manifest %q: %w", target, err)
	}

	var manifest models.MCPManifest
	// Strip UTF-8 BOM if present
	if len(data) >= 3 && data[0] == 0xEF && data[1] == 0xBB && data[2] == 0xBF {
		data = data[3:]
	}
	if err := json.Unmarshal(data, &manifest); err != nil {
		return fmt.Errorf("could not parse %q. If this file was created on Windows, it may have a UTF-8 BOM marker. Try re-saving in UTF-8 without BOM, or use a different text editor. Original error: %w", target, err)
	}

	ctx.Manifest = &manifest
	return nil
}
