package models

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strings"
)

func HashIdentity(s string) string { v := sha256.Sum256([]byte(s)); return hex.EncodeToString(v[:]) }

// FinalizeEvidence assigns stable rule/component groups. Multiple occurrences
// of one rule in one component intentionally share an identity.
func (r *Report) FinalizeEvidence() {
	if r.TargetHash == "" {
		r.TargetHash = HashIdentity(r.Target)
	}
	for i := range r.Findings {
		f := &r.Findings[i]
		if f.Fingerprint == "" {
			b, _ := json.Marshal([]string{r.TargetHash, f.ID, strings.ReplaceAll(f.Location.File, "\\", "/"), f.Location.ToolName})
			f.Fingerprint = HashIdentity(string(b))
		}
		if f.Confidence == "" {
			f.Confidence = "needs_review"
			if f.ID == "CVE-001" {
				f.Confidence = "advisory_match"
			}
		}
	}
	sort.SliceStable(r.Findings, func(i, j int) bool {
		a, b := r.Findings[i], r.Findings[j]
		if a.Fingerprint != b.Fingerprint {
			return a.Fingerprint < b.Fingerprint
		}
		if a.Location.Line != b.Location.Line {
			return a.Location.Line < b.Location.Line
		}
		return a.Description < b.Description
	})
}

type Verification struct {
	State      string   `json:"state"`
	Resolved   []string `json:"resolved"`
	Persistent []string `json:"persistent"`
	New        []string `json:"new"`
	Limitation string   `json:"limitation"`
}

func VerifyReports(before, after *Report) (*Verification, error) {
	for _, r := range []*Report{before, after} {
		if r == nil || r.SchemaVersion != 2 || r.Coverage.State != "completed" || len(r.Coverage.Surfaces) == 0 || len(r.Coverage.Inputs) == 0 || len(r.Coverage.SelectedChecks) == 0 || len(r.TargetHash) != 64 {
			return nil, fmt.Errorf("verification requires complete schema-2 reports")
		}
		if r.Coverage.Advisories != "completed" && r.Coverage.Advisories != "skipped" && r.Coverage.Advisories != "not_applicable" {
			return nil, fmt.Errorf("advisory verification incomplete")
		}
		if r.Summary.Total != len(r.Findings) {
			return nil, fmt.Errorf("inconsistent report summary")
		}
		for _, f := range r.Findings {
			if len(f.Fingerprint) != 64 {
				return nil, fmt.Errorf("report missing stable identities")
			}
			if _, err := hex.DecodeString(f.Fingerprint); err != nil {
				return nil, fmt.Errorf("invalid finding identity")
			}
		}
	}
	if before.TargetHash != after.TargetHash || before.ScanMode != after.ScanMode || before.MinSeverity != after.MinSeverity || !reflect.DeepEqual(before.Coverage, after.Coverage) {
		return nil, fmt.Errorf("verification scope, policy or input inventory changed; findings remain unverified")
	}
	out := &Verification{State: "completed", Resolved: []string{}, Persistent: []string{}, New: []string{}, Limitation: "Resolved means the selected checks no longer detected this rule/component group in equivalent completed coverage. This is not proof of exploit prevention, absence of compromise, or authenticity of unsigned reports."}
	a, b := map[string]bool{}, map[string]bool{}
	for _, f := range before.Findings {
		a[f.Fingerprint] = true
	}
	for _, f := range after.Findings {
		b[f.Fingerprint] = true
	}
	for id := range a {
		if b[id] {
			out.Persistent = append(out.Persistent, id)
		} else {
			out.Resolved = append(out.Resolved, id)
		}
	}
	for id := range b {
		if !a[id] {
			out.New = append(out.New, id)
		}
	}
	sort.Strings(out.Resolved)
	sort.Strings(out.Persistent)
	sort.Strings(out.New)
	return out, nil
}
