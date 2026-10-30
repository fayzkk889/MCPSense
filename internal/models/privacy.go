package models

import (
	"regexp"
	"strings"
)

var credentialText = regexp.MustCompile(`(?i)((?:api[_-]?key|access[_-]?token|token|password|passwd|secret|authorization)\s*[=:]\s*["']?)([^\s"',;]+)`)
var providerToken = regexp.MustCompile(`\b(?:sk-[A-Za-z0-9_-]{12,}|gh[pousr]_[A-Za-z0-9_]{12,}|AKIA[A-Z0-9]{16})\b`)
var credentialURL = regexp.MustCompile(`(?i)\b(?:https?|file)://[^\s<>"']+`)

// RedactText is best-effort pattern redaction, not a guarantee for arbitrary secrets.
// URL credentials, queries and fragments are omitted in full (including their keys).
func RedactText(s string) string {
	s = credentialURL.ReplaceAllStringFunc(s, func(raw string) string {
		schemeEnd := strings.Index(raw, "://") + 3
		tail := raw[schemeEnd:]
		if at := strings.Index(tail, "@"); at >= 0 {
			tail = "[REDACTED]@" + tail[at+1:]
		}
		if at := strings.IndexAny(tail, "?#"); at >= 0 {
			tail = tail[:at] + "?[REDACTED]"
		}
		return raw[:schemeEnd] + tail
	})
	s = credentialText.ReplaceAllString(s, "${1}[REDACTED]")
	return providerToken.ReplaceAllString(s, "[REDACTED]")
}

// ProtectedCopy never exports full before/after content. Known values supplement
// pattern redaction, e.g. credentials supplied through client config environment.
func (r *Report) ProtectedCopy(known []string) *Report {
	out := *r
	out.Assessment = r.SecurityAssessment()
	out.Findings = append(make([]Finding, 0, len(r.Findings)), r.Findings...)
	protect := func(s string) string {
		for _, v := range known {
			if v != "" {
				s = strings.ReplaceAll(s, v, "[REDACTED]")
			}
		}
		return RedactText(s)
	}
	out.Target = protect(r.Target)
	if r.Dependencies != nil {
		inventory := *r.Dependencies
		inventory.Input = protect(inventory.Input)
		inventory.Packages = append([]Dependency{}, inventory.Packages...)
		for i := range inventory.Packages {
			dep := &inventory.Packages[i]
			dep.Path, dep.Name, dep.Version = protect(dep.Path), protect(dep.Name), protect(dep.Version)
		}
		out.Dependencies = &inventory
	}
	for i := range out.Findings {
		f := &out.Findings[i]
		if f.Advisory != nil {
			a := *f.Advisory
			a.ID, a.Applicability, a.FeedURL = protect(a.ID), protect(a.Applicability), protect(a.FeedURL)
			a.ReviewedURL, a.ReviewedAt, a.ReviewNote = protect(a.ReviewedURL), protect(a.ReviewedAt), protect(a.ReviewNote)
			f.Advisory = &a
		}
		f.Title = protect(f.Title)
		f.Description = protect(f.Description)
		f.Remediation = protect(f.Remediation)
		f.Location.File = protect(f.Location.File)
		f.Location.ToolName = protect(f.Location.ToolName)
		f.DiffOld = ""
		f.DiffNew = ""
	}
	return &out
}
