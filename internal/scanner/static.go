package scanner

import (
	"encoding/json"
	"fmt"
	"github.com/fayzkk889/MCPSense/internal/checks"
	"github.com/fayzkk889/MCPSense/internal/models"
	"github.com/fayzkk889/MCPSense/internal/utils"
	"os"
	"path/filepath"
)

func (s *Scanner) scanStatic(target string, ctx *checks.ScanContext) error {
	files, err := utils.DiscoverSourceFiles(target)
	if err != nil {
		return err
	}
	ctx.SourceFiles = files
	total := 0
	count := 0
	return filepath.WalkDir(target, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			if utils.SkipDirectory(d.Name()) && path != target {
				return filepath.SkipDir
			}
			return nil
		}
		switch d.Name() {
		case "manifest.json", "mcp.json", "mcp-config.json", "mcpconfig.json", ".mcp.json", "claude_desktop_config.json", "package.json":
		default:
			return nil
		}
		count++
		if count > 10000 {
			return fmt.Errorf("configuration file count limit exceeded")
		}
		b, err := utils.ReadInput(path)
		if err != nil {
			return err
		}
		total += len(b)
		if total > utils.MaxScanBytes {
			return fmt.Errorf("configuration byte budget exceeded")
		}
		b = []byte(stripBOM(string(b)))
		var raw map[string]json.RawMessage
		if json.Unmarshal(b, &raw) != nil {
			return fmt.Errorf("invalid discovered JSON input; scan coverage incomplete")
		}
		if d.Name() == "package.json" {
			embedded, ok := raw["mcp"]
			if !ok {
				return nil
			}
			b = embedded
			if json.Unmarshal(b, &raw) != nil {
				return fmt.Errorf("invalid embedded MCP metadata")
			}
		}
		if _, ok := raw["mcpServers"]; ok {
			return mergeConfig(b, path, ctx)
		}
		if _, ok := raw["servers"]; ok {
			return mergeConfig(b, path, ctx)
		}
		if raw["name"] == nil && raw["tools"] == nil && raw["resources"] == nil && raw["prompts"] == nil {
			return fmt.Errorf("discovered MCP candidate has an unsupported shape; scan explicitly after review")
		}
		if ctx.Manifest != nil {
			return fmt.Errorf("multiple manifests discovered; scan each with --mode manifest to preserve component boundaries")
		}
		var m models.MCPManifest
		if json.Unmarshal(b, &m) != nil {
			return fmt.Errorf("invalid discovered manifest")
		}
		ctx.Manifest = &m
		ctx.ManifestFile = path
		ctx.InputPaths = append(ctx.InputPaths, path)
		return nil
	})
}
func parseConfig(b []byte) (*models.MCPClientConfig, error) {
	var raw map[string]json.RawMessage
	if json.Unmarshal(b, &raw) != nil {
		return nil, fmt.Errorf("invalid MCP client configuration JSON")
	}
	entries, ok := raw["mcpServers"]
	if !ok {
		entries, ok = raw["servers"]
	}
	if !ok {
		return nil, fmt.Errorf("configuration must contain mcpServers or servers")
	}
	var servers map[string]models.MCPServerEntry
	if json.Unmarshal(entries, &servers) != nil || servers == nil {
		return nil, fmt.Errorf("invalid server map")
	}
	return &models.MCPClientConfig{MCPServers: servers}, nil
}
func mergeConfig(b []byte, path string, ctx *checks.ScanContext) error {
	c, err := parseConfig(b)
	if err != nil {
		return err
	}
	if ctx.ClientConfig == nil {
		ctx.ClientConfig = &models.MCPClientConfig{MCPServers: map[string]models.MCPServerEntry{}}
	}
	for name, e := range c.MCPServers {
		if _, ok := ctx.ClientConfig.MCPServers[name]; ok {
			return fmt.Errorf("duplicate server names across configurations; scan configs separately")
		}
		ctx.ClientConfig.MCPServers[name] = e
		if ctx.ComponentFiles == nil {
			ctx.ComponentFiles = map[string]string{}
		}
		ctx.ComponentFiles[name] = path
	}
	ctx.InputPaths = append(ctx.InputPaths, path)
	return nil
}
func (s *Scanner) scanConfig(target string, ctx *checks.ScanContext) error {
	b, err := utils.ReadInput(target)
	if err != nil {
		return err
	}
	c, err := parseConfig([]byte(stripBOM(string(b))))
	if err != nil {
		return err
	}
	ctx.ClientConfig = c
	ctx.ComponentFiles = map[string]string{}
	for name := range c.MCPServers {
		ctx.ComponentFiles[name] = target
	}
	return nil
}
