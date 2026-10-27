package drift

import (
	"encoding/json"
	"github.com/fayzkk889/MCPSense/internal/models"
	"sort"
)

// MetadataSnap is an additive extension of format 2. Its absence means these
// fields were never captured, not that their original values were empty.
type MetadataSnap struct {
	Version        int               `json:"version"`
	CatalogHash    string            `json:"catalog_hash,omitempty"`
	ServerTextHash string            `json:"server_text_hash"`
	Tools          map[string]string `json:"tools"`
	Prompts        map[string]string `json:"prompts"`
}

func buildMetadata(m *models.MCPManifest) *MetadataSnap {
	s := &MetadataSnap{Version: 1, ServerTextHash: digest([]string{m.Description, m.Instructions}), Tools: map[string]string{}, Prompts: map[string]string{}}
	// Additional full recognized-catalog digest for the opt-in gate. Keep
	// ordinary historical comparisons compatible; old snapshots lack this
	// digest and cannot satisfy strict matching. Unknown extensions are not
	// represented by MCPManifest and remain explicitly out of scope.
	catalog := *m
	catalog.Tools = append([]models.MCPTool{}, m.Tools...)
	catalog.Resources = append([]models.MCPResource{}, m.Resources...)
	catalog.Prompts = append([]models.MCPPrompt{}, m.Prompts...)
	sort.Slice(catalog.Tools, func(i, j int) bool { return catalog.Tools[i].Name < catalog.Tools[j].Name })
	sort.Slice(catalog.Resources, func(i, j int) bool { return catalog.Resources[i].URI < catalog.Resources[j].URI })
	sort.Slice(catalog.Prompts, func(i, j int) bool { return catalog.Prompts[i].Name < catalog.Prompts[j].Name })
	encoded, _ := json.Marshal(catalog)
	s.CatalogHash = digest(canonicalJSON(encoded))
	for _, tool := range m.Tools {
		s.Tools[hash(tool.Name)] = digest([]interface{}{tool.Title, canonicalJSON(tool.OutputSchema)})
	}
	for _, prompt := range m.Prompts {
		s.Prompts[hash(prompt.Name)] = digest([]interface{}{prompt.Description, canonicalJSON(prompt.Arguments)})
	}
	return s
}

func supportedMetadata(s *Snapshot) bool { return s.Metadata == nil || s.Metadata.Version == 1 }

// ComparisonCoverage describes comparisons actually possible with both snapshots.
// It deliberately does not claim detection of removed entries or runtime changes.
func ComparisonCoverage(before, after *Snapshot) ([]string, string) {
	var fields []string
	if after.Tools != nil || after.Resources != nil {
		fields = append(fields, "tools.additions", "tools.description", "tools.inputSchema", "tools.annotations", "resources.additions", "resources.metadata", "auth.removal")
	}
	if after.Servers != nil {
		fields = append(fields, "servers.existing_configuration_without_env_values")
	}
	if before.Metadata != nil && after.Metadata != nil {
		fields = append(fields, "server.description", "server.instructions", "tools.title", "tools.outputSchema", "prompts.additions", "prompts.description", "prompts.arguments")
	} else if after.Metadata != nil {
		return fields, "Older baseline lacks server text, tool titles/output schemas and prompts. Review the target, then use --update-baseline to capture them; these fields were not compared."
	}
	return fields, ""
}
