package scanner

import (
	"encoding/json"
	"fmt"
	"github.com/fayzkk889/MCPSense/internal/utils"

	"github.com/fayzkk889/MCPSense/internal/checks"
	"github.com/fayzkk889/MCPSense/internal/models"
)

// scanManifest loads and parses an MCP manifest JSON file into the scan context.
func (s *Scanner) scanManifest(target string, ctx *checks.ScanContext) error {
	data, err := utils.ReadInput(target)
	if err != nil {
		return fmt.Errorf("reading manifest %q: %w", target, err)
	}

	var manifest models.MCPManifest
	// Strip UTF-8 BOM if present
	if len(data) >= 3 && data[0] == 0xEF && data[1] == 0xBB && data[2] == 0xBF {
		data = data[3:]
	}
	if err := json.Unmarshal(data, &manifest); err != nil {
		return fmt.Errorf("invalid manifest JSON in %q: %w; check JSON syntax and field types", target, err)
	}

	ctx.Manifest = &manifest
	ctx.ManifestFile = target
	return nil
}
