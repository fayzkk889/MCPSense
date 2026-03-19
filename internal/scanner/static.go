package scanner

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	"github.com/faizan/mcpsense/internal/checks"
	"github.com/faizan/mcpsense/internal/models"
	"github.com/faizan/mcpsense/internal/utils"
)

// scanStatic performs static analysis on the target directory.
func (s *Scanner) scanStatic(target string, ctx *checks.ScanContext) error {
	// Discover and read all source files.
	sourceFiles, err := utils.DiscoverSourceFiles(target)
	if err != nil {
		return err
	}
	ctx.SourceFiles = sourceFiles

	// Try to locate and parse a manifest file.
	manifest := s.tryLoadManifest(target)
	if manifest != nil {
		ctx.Manifest = manifest
	}

	return nil
}

// tryLoadManifest attempts to find and parse an MCP manifest in the target directory.
func (s *Scanner) tryLoadManifest(root string) *models.MCPManifest {
	candidates := []string{
		filepath.Join(root, "mcp.json"),
		filepath.Join(root, "mcp-config.json"),
		filepath.Join(root, "mcpconfig.json"),
		filepath.Join(root, ".mcp.json"),
	}

	// Also look for manifest.json in immediate subdirectories.
	entries, _ := os.ReadDir(root)
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		candidates = append(candidates,
			filepath.Join(root, entry.Name(), "mcp.json"),
			filepath.Join(root, entry.Name(), "manifest.json"),
		)
	}
	// Check for manifest.json in the root itself.
	candidates = append(candidates, filepath.Join(root, "manifest.json"))

	for _, path := range candidates {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		// Try direct MCPManifest parse.
		var manifest models.MCPManifest
		if err := json.Unmarshal(data, &manifest); err == nil && manifest.Name != "" {
			return &manifest
		}
		// Try package.json with mcp field.
		if strings.HasSuffix(path, "package.json") {
			manifest := tryExtractMCPFromPackageJSON(data)
			if manifest != nil {
				return manifest
			}
		}
	}
	return nil
}

// tryExtractMCPFromPackageJSON tries to extract an MCP manifest embedded in package.json.
func tryExtractMCPFromPackageJSON(data []byte) *models.MCPManifest {
	var pkg map[string]json.RawMessage
	if err := json.Unmarshal(data, &pkg); err != nil {
		return nil
	}
	raw, ok := pkg["mcp"]
	if !ok {
		return nil
	}
	var manifest models.MCPManifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return nil
	}
	return &manifest
}
