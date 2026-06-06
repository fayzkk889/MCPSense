package drift

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/fayzkk889/MCPSense/internal/models"
)

// Snapshot captures the security-relevant surface of an MCP server at a point in time.
type Snapshot struct {
	Target    string                `json:"target"`
	Mode      string                `json:"mode"`
	CreatedAt time.Time             `json:"created_at"`
	Tools     map[string]ToolSnap   `json:"tools,omitempty"`     // keyed by tool name
	Resources map[string]string     `json:"resources,omitempty"` // uri -> name
	AuthType  string                `json:"auth_type,omitempty"`
	Servers   map[string]ServerSnap `json:"servers,omitempty"` // config mode, keyed by server name
}

// ToolSnap captures a single tool's security surface.
type ToolSnap struct {
	Description     string `json:"description"`            // stored full for diff display
	DescriptionHash string `json:"description_hash"`
	SchemaHash      string `json:"schema_hash"`
	AnnotationsHash string `json:"annotations_hash,omitempty"`
	ReadOnly        *bool  `json:"read_only,omitempty"` // nil if no annotation, tracks read-only hint
}

// ServerSnap captures a config server entry's security surface.
type ServerSnap struct {
	Command string   `json:"command"`
	Args    []string `json:"args"`
	EnvKeys []string `json:"env_keys"` // KEYS ONLY. Never store env values (they are secrets).
}

func hash(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// BuildSnapshot constructs a Snapshot from the scanned manifest and/or client config.
// Either argument may be nil depending on scan mode.
func BuildSnapshot(manifest *models.MCPManifest, config *models.MCPClientConfig, target, mode string) *Snapshot {
	snap := &Snapshot{
		Target:    target,
		Mode:      mode,
		CreatedAt: time.Now().UTC(),
	}

	if manifest != nil {
		snap.Tools = make(map[string]ToolSnap)
		for _, tool := range manifest.Tools {
			ts := ToolSnap{
				Description:     tool.Description,
				DescriptionHash: hash(tool.Description),
				SchemaHash:      hash(string(tool.InputSchema)),
			}
			
			if tool.Annotations != nil {
				annJSON, _ := json.Marshal(tool.Annotations)
				ts.AnnotationsHash = hash(string(annJSON))
				ts.ReadOnly = tool.Annotations.ReadOnlyHint
			}
			
			snap.Tools[tool.Name] = ts
		}

		if len(manifest.Resources) > 0 {
			snap.Resources = make(map[string]string)
			for _, res := range manifest.Resources {
				snap.Resources[res.URI] = res.Name
			}
		}

		if manifest.Auth != nil {
			snap.AuthType = manifest.Auth.Type
		}
	}

	if config != nil {
		snap.Servers = make(map[string]ServerSnap)
		for name, entry := range config.MCPServers {
			envKeys := make([]string, 0, len(entry.Env))
			for k := range entry.Env {
				envKeys = append(envKeys, k)
			}
			sort.Strings(envKeys)
			snap.Servers[name] = ServerSnap{
				Command: entry.Command,
				Args:    entry.Args,
				EnvKeys: envKeys,
			}
		}
	}

	return snap
}

// Diff compares a baseline snapshot against the current one and returns drift findings.
func Diff(baseline, current *Snapshot) []models.Finding {
	var findings []models.Finding

	baselineDate := baseline.CreatedAt.Format("2006-01-02")

	// --- Tool drift (manifest / live mode) ---
	for name, cur := range current.Tools {
		prev, existed := baseline.Tools[name]
		if !existed {
			// DRIFT-001: new tool added
			findings = append(findings, models.Finding{
				ID:          "DRIFT-001",
				Title:       fmt.Sprintf("New tool %q added since baseline", name),
				Description: fmt.Sprintf("Tool %q did not exist in the baseline saved on %s. A server adding new tools after approval is a privilege escalation vector. Review whether this addition is expected.", name, baselineDate),
				Severity:    models.SeverityMedium,
				Category:    models.CategoryDrift,
				OWASP:       models.OWASPForCheckID("DRIFT-001"),
				Location:    models.Location{ToolName: name},
				Remediation: "Verify this tool addition is legitimate. If expected, accept it with: mcpsense scan <target> --update-baseline. If unexpected, do not connect this server.",
			})
			continue
		}

		// DRIFT-002: description changed (rug-pull signal)
		if prev.DescriptionHash != cur.DescriptionHash {
			findings = append(findings, models.Finding{
				ID:          "DRIFT-002",
				Title:       fmt.Sprintf("Tool description changed for %q since baseline", name),
				Description: fmt.Sprintf("The description of tool %q changed since the baseline saved on %s. Mid-life description changes are the signature of a rug-pull attack, where a server ships a benign description, gets approved, then swaps in malicious instructions.", name, baselineDate),
				Severity:    models.SeverityHigh,
				Category:    models.CategoryDrift,
				OWASP:       models.OWASPForCheckID("DRIFT-002"),
				Location:    models.Location{ToolName: name},
				Remediation: "Review the description change carefully for injected instructions. If legitimate, accept with --update-baseline. If suspicious, disconnect this server immediately.",
				DiffOld:     prev.Description,
				DiffNew:     cur.Description,
			})
		}

		// DRIFT-003: input schema changed
		if prev.SchemaHash != cur.SchemaHash {
			findings = append(findings, models.Finding{
				ID:          "DRIFT-003",
				Title:       fmt.Sprintf("Tool input schema changed for %q since baseline", name),
				Description: fmt.Sprintf("The input schema of tool %q changed since the baseline saved on %s. New or altered parameters can expand what a tool accepts, potentially introducing injection surface.", name, baselineDate),
				Severity:    models.SeverityMedium,
				Category:    models.CategoryDrift,
				OWASP:       models.OWASPForCheckID("DRIFT-003"),
				Location:    models.Location{ToolName: name},
				Remediation: "Review the schema change for new parameters that could carry untrusted input. Accept with --update-baseline if expected.",
			})
		}

		// DRIFT-004: annotation weakened (e.g. read-only hint removed or flipped to false)
		wasReadOnly := prev.ReadOnly != nil && *prev.ReadOnly
		nowNotReadOnly := cur.ReadOnly == nil || !*cur.ReadOnly
		if wasReadOnly && nowNotReadOnly {
			findings = append(findings, models.Finding{
				ID:          "DRIFT-004",
				Title:       fmt.Sprintf("Tool %q lost its read-only annotation since baseline", name),
				Description: fmt.Sprintf("Tool %q was marked read-only in the baseline saved on %s but no longer is. A tool gaining write capability after approval is a serious privilege escalation.", name, baselineDate),
				Severity:    models.SeverityHigh,
				Category:    models.CategoryDrift,
				OWASP:       models.OWASPForCheckID("DRIFT-004"),
				Location:    models.Location{ToolName: name},
				Remediation: "A read-only tool becoming write-capable is a major red flag. Verify this change is intentional before continuing to use this server.",
			})
		}
	}

	// --- Resource drift ---
	for uri, name := range current.Resources {
		if _, existed := baseline.Resources[uri]; !existed {
			findings = append(findings, models.Finding{
				ID:          "DRIFT-005",
				Title:       fmt.Sprintf("New resource exposed: %q since baseline", uri),
				Description: fmt.Sprintf("Resource %q (%s) was not exposed in the baseline saved on %s. New resources expand the data the server can reach.", uri, name, baselineDate),
				Severity:    models.SeverityMedium,
				Category:    models.CategoryDrift,
				OWASP:       models.OWASPForCheckID("DRIFT-005"),
				Location:    models.Location{File: uri},
				Remediation: "Verify this resource exposure is expected. Accept with --update-baseline if legitimate.",
			})
		}
	}

	// --- Auth drift ---
	if baseline.AuthType != "" && current.AuthType == "" {
		findings = append(findings, models.Finding{
			ID:          "DRIFT-006",
			Title:       "Authentication removed since baseline",
			Description: fmt.Sprintf("The server declared auth type %q in the baseline saved on %s but now declares none. Removing authentication exposes all tools to unauthenticated access.", baseline.AuthType, baselineDate),
			Severity:    models.SeverityCritical,
			Category:    models.CategoryDrift,
			OWASP:       models.OWASPForCheckID("DRIFT-006"),
			Remediation: "A server dropping authentication is a critical security regression. Do not use this server until you confirm why auth was removed.",
			DiffOld:     baseline.AuthType,
			DiffNew:     "(none)",
		})
	}

	// --- Config server drift ---
	for name, cur := range current.Servers {
		prev, existed := baseline.Servers[name]
		if !existed {
			continue // a brand new server entry is the user's own config change, not server-side drift
		}
		changed := []string{}
		if prev.Command != cur.Command {
			changed = append(changed, fmt.Sprintf("command (%q -> %q)", prev.Command, cur.Command))
		}
		if strings.Join(prev.Args, " ") != strings.Join(cur.Args, " ") {
			changed = append(changed, "args")
		}
		if strings.Join(prev.EnvKeys, ",") != strings.Join(cur.EnvKeys, ",") {
			changed = append(changed, "env keys")
		}
		if len(changed) > 0 {
			findings = append(findings, models.Finding{
				ID:          "DRIFT-007",
				Title:       fmt.Sprintf("Config for server %q changed since baseline", name),
				Description: fmt.Sprintf("The config entry for server %q changed since the baseline saved on %s: %s.", name, baselineDate, strings.Join(changed, ", ")),
				Severity:    models.SeverityHigh,
				Category:    models.CategoryDrift,
				OWASP:       models.OWASPForCheckID("DRIFT-007"),
				Location:    models.Location{File: name},
				Remediation: "Verify these config changes are intentional. A changed command or args can redirect the server to malicious code. Accept with --update-baseline if expected.",
				DiffOld:     fmt.Sprintf("command=%q args=%v env=%v", prev.Command, prev.Args, prev.EnvKeys),
				DiffNew:     fmt.Sprintf("command=%q args=%v env=%v", cur.Command, cur.Args, cur.EnvKeys),
			})
		}
	}

	return findings
}

// MarshalSnapshot serializes a snapshot to JSON.
func MarshalSnapshot(snap *Snapshot) ([]byte, error) {
	return json.MarshalIndent(snap, "", "  ")
}
