package drift

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/fayzkk889/MCPSense/internal/models"
	"sort"
	"time"
)

const FormatVersion = 2

// Snapshot retains change digests, never descriptions, commands, arguments or URLs.
// Digests are change indicators, not encryption or protection against guessing.
type Snapshot struct {
	FormatVersion int                 `json:"format_version"`
	Target        string              `json:"target_hash"`
	Mode          string              `json:"mode"`
	CreatedAt     time.Time           `json:"created_at"`
	Tools         map[string]ToolSnap `json:"tools,omitempty"`
	Resources     map[string]string   `json:"resources,omitempty"`
	HasAuth       bool                `json:"has_auth"`
	Servers       map[string]string   `json:"servers,omitempty"`
	Metadata      *MetadataSnap       `json:"metadata,omitempty"`
}
type ToolSnap struct {
	DescriptionHash string `json:"description_hash"`
	SchemaHash      string `json:"schema_hash"`
	AnnotationsHash string `json:"annotations_hash,omitempty"`
	ReadOnly        bool   `json:"read_only"`
}

func hash(s string) string        { v := sha256.Sum256([]byte(s)); return hex.EncodeToString(v[:]) }
func digest(v interface{}) string { b, _ := json.Marshal(v); return hash(string(b)) }
func BuildSnapshot(m *models.MCPManifest, c *models.MCPClientConfig, target, mode string) *Snapshot {
	s := &Snapshot{FormatVersion: FormatVersion, Target: hash(target), Mode: mode, CreatedAt: time.Now().UTC()}
	if m != nil {
		s.Tools = map[string]ToolSnap{}
		for _, t := range m.Tools {
			ts := ToolSnap{DescriptionHash: hash(t.Description), SchemaHash: digest(canonicalJSON(t.InputSchema))}
			if t.Annotations != nil {
				ts.AnnotationsHash = digest(t.Annotations)
				ts.ReadOnly = t.Annotations.ReadOnlyHint != nil && *t.Annotations.ReadOnlyHint
			}
			s.Tools[hash(t.Name)] = ts
		}
		s.Resources = map[string]string{}
		for _, r := range m.Resources {
			s.Resources[hash(r.URI)] = digest(r)
		}
		s.HasAuth = m.Auth != nil && m.Auth.Type != "" && m.Auth.Type != "none"
		s.Metadata = buildMetadata(m)
	}
	if c != nil {
		s.Servers = map[string]string{}
		for name, e := range c.MCPServers {
			keys := make([]string, 0, len(e.Env))
			for k := range e.Env {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			// Environment values are deliberately excluded even from the digest.
			s.Servers[hash(name)] = digest(struct {
				Command   string
				Args      []string
				EnvKeys   []string
				URL, Type string
			}{e.Command, e.Args, keys, e.URL, e.Type})
		}
	}
	return s
}
func Diff(before, after *Snapshot) []models.Finding {
	var fs []models.Finding
	add := func(id, title, key string, sev models.Severity) {
		fs = append(fs, models.Finding{ID: id, Title: title, Description: fmt.Sprintf("Security metadata changed since baseline %s. Review the original authorized target locally; raw values are not retained.", before.CreatedAt.Format("2006-01-02")), Severity: sev, Category: models.CategoryDrift, OWASP: models.OWASPForCheckID(id), Location: models.Location{ToolName: key}, Remediation: "Review this metadata change. If expected, accept it with --update-baseline."})
	}
	for key, cur := range after.Tools {
		prev, ok := before.Tools[key]
		if !ok {
			add("DRIFT-001", "New tool metadata", key, models.SeverityMedium)
			continue
		}
		if prev.DescriptionHash != cur.DescriptionHash {
			add("DRIFT-002", "Tool description changed", key, models.SeverityHigh)
		}
		if prev.SchemaHash != cur.SchemaHash {
			add("DRIFT-003", "Tool input schema changed", key, models.SeverityMedium)
		}
		if prev.ReadOnly && !cur.ReadOnly {
			add("DRIFT-004", "Tool read-only hint removed or changed (requires review)", key, models.SeverityHigh)
		} else if prev.AnnotationsHash != cur.AnnotationsHash {
			add("DRIFT-008", "Tool annotations changed (requires review)", key, models.SeverityMedium)
		}
	}
	for key, cur := range after.Resources {
		if prev, ok := before.Resources[key]; !ok {
			add("DRIFT-005", "New resource metadata", key, models.SeverityMedium)
		} else if prev != cur {
			add("DRIFT-009", "Resource metadata changed", key, models.SeverityHigh)
		}
	}
	if before.HasAuth && !after.HasAuth {
		add("DRIFT-006", "Authentication declaration removed (requires review)", "", models.SeverityCritical)
	}
	for key, cur := range after.Servers {
		if prev, ok := before.Servers[key]; ok && prev != cur {
			add("DRIFT-007", "Server configuration changed", key, models.SeverityHigh)
		}
	}
	if before.Metadata != nil && after.Metadata != nil {
		if before.Metadata.ServerTextHash != after.Metadata.ServerTextHash {
			add("DRIFT-011", "Server description or instructions changed", "", models.SeverityHigh)
		}
		for key, cur := range after.Metadata.Tools {
			if prev, ok := before.Metadata.Tools[key]; ok && prev != cur {
				add("DRIFT-010", "Tool title or output schema changed", key, models.SeverityHigh)
			}
		}
		for key, cur := range after.Metadata.Prompts {
			if prev, ok := before.Metadata.Prompts[key]; !ok {
				add("DRIFT-012", "New prompt metadata", key, models.SeverityMedium)
			} else if prev != cur {
				add("DRIFT-013", "Prompt description or arguments changed", key, models.SeverityHigh)
			}
		}
	}
	sort.Slice(fs, func(i, j int) bool {
		if fs[i].ID != fs[j].ID {
			return fs[i].ID < fs[j].ID
		}
		return fs[i].Location.ToolName < fs[j].Location.ToolName
	})
	return fs
}
func MarshalSnapshot(s *Snapshot) ([]byte, error) {
	if s.FormatVersion != FormatVersion || !supportedMetadata(s) {
		return nil, fmt.Errorf("unsupported baseline format; recreate with --update-baseline")
	}
	return json.MarshalIndent(s, "", "  ")
}

// Canonicalize object keys and whitespace without rounding numeric constraints.
func canonicalJSON(raw json.RawMessage) interface{} {
	var value interface{}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if !json.Valid(raw) || decoder.Decode(&value) != nil {
		return string(raw)
	}
	return value
}
