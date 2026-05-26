package scanner

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/fayzkk889/MCPSense/internal/checks"
	"github.com/fayzkk889/MCPSense/internal/models"
	"github.com/fayzkk889/MCPSense/internal/utils"
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

	// Try to locate and parse MCP client config files.
	clientConfig := s.tryLoadClientConfig(target)
	if clientConfig != nil {
		ctx.ClientConfig = clientConfig
	}

	return nil
}

// scanConfig loads and parses an MCP client config file for security analysis.
func (s *Scanner) scanConfig(target string, ctx *checks.ScanContext) error {
	data, err := os.ReadFile(target)
	if err != nil {
		return fmt.Errorf("reading config %q: %w", target, err)
	}
	// Strip UTF-8 BOM if present
	if len(data) >= 3 && data[0] == 0xEF && data[1] == 0xBB && data[2] == 0xBF {
		data = data[3:]
	}
	var config models.MCPClientConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return fmt.Errorf("could not parse %q. If this file was created on Windows, it may have a UTF-8 BOM marker. Try re-saving in UTF-8 without BOM, or use a different text editor. Original error: %w", target, err)
	}
	ctx.ClientConfig = &config
	return nil
}

// tryLoadClientConfig attempts to find and parse MCP client config files in the target directory.
// These are the config files that IDEs (Cursor, Claude Desktop, VS Code) use to define which
// MCP servers to connect to. They are a critical attack surface for command injection.
func (s *Scanner) tryLoadClientConfig(root string) *models.MCPClientConfig {
	candidates := []string{
		filepath.Join(root, "mcp.json"),
		filepath.Join(root, ".mcp.json"),
		filepath.Join(root, ".cursor", "mcp.json"),
		filepath.Join(root, ".vscode", "mcp.json"),
		filepath.Join(root, "claude_desktop_config.json"),
	}

	// Check home directory configs if scanning the home dir
	home, err := os.UserHomeDir()
	if err == nil {
		candidates = append(candidates,
			filepath.Join(home, ".claude.json"),
			filepath.Join(home, "Library", "Application Support", "Claude", "claude_desktop_config.json"),
			filepath.Join(home, ".config", "Claude", "claude_desktop_config.json"),
			filepath.Join(home, "AppData", "Roaming", "Claude", "claude_desktop_config.json"),
		)
	}

	for _, path := range candidates {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		// Strip UTF-8 BOM if present
		if len(data) >= 3 && data[0] == 0xEF && data[1] == 0xBB && data[2] == 0xBF {
			data = data[3:]
		}
		var config models.MCPClientConfig
		if err := json.Unmarshal(data, &config); err == nil && len(config.MCPServers) > 0 {
			return &config
		}
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
		// Strip UTF-8 BOM if present
		if len(data) >= 3 && data[0] == 0xEF && data[1] == 0xBB && data[2] == 0xBF {
			data = data[3:]
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
