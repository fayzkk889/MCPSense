package scanner

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/faizan/mcpsense/internal/checks"
	"github.com/faizan/mcpsense/internal/models"
)

// scanManifest loads and parses an MCP manifest JSON file into the scan context.
func (s *Scanner) scanManifest(target string, ctx *checks.ScanContext) error {
	data, err := os.ReadFile(target)
	if err != nil {
		return fmt.Errorf("reading manifest %q: %w", target, err)
	}

	var manifest models.MCPManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return fmt.Errorf("parsing manifest %q: %w", target, err)
	}

	ctx.Manifest = &manifest
	return nil
}
