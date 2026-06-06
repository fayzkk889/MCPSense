package cve

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

const (
	osvBatchURL  = "https://api.osv.dev/v1/querybatch"
	osvSingleURL = "https://api.osv.dev/v1/query"
	// Total network budget for the whole CVE phase.
	totalBudget = 4 * time.Second
	// Fast probe: if the first call fails this fast, assume offline and skip the rest.
	probeBudget = 500 * time.Millisecond
)

// Package identifies a package to query.
type Package struct {
	Name      string
	Version   string // may be empty (unpinned)
	Ecosystem string // "npm", "PyPI", "Go", etc.
	Server    string // MCP server entry name this package came from (for finding location)
}

// Vuln is a normalized vulnerability result.
type Vuln struct {
	ID           string
	Summary      string
	CVSS         float64
	FixedVersion string
}

// Result pairs a package with the vulns found for it.
type Result struct {
	Package Package
	Vulns   []Vuln
}

// EcosystemForCommand maps an MCP server command to an OSV ecosystem.
// Returns "" if the command does not correspond to a known package ecosystem.
func EcosystemForCommand(command string) string {
	switch strings.ToLower(strings.TrimSpace(command)) {
	case "npx", "npm", "node":
		return "npm"
	case "uvx", "uv", "pip", "pipx", "python", "python3":
		return "PyPI"
	default:
		return ""
	}
}

// Client queries OSV.dev with built-in timeout and offline handling.
type Client struct {
	http    *http.Client
	offline bool // set true after a fast-failing probe so we stop trying
}

func NewClient() *Client {
	return &Client{
		http: &http.Client{Timeout: totalBudget},
	}
}

type osvQuery struct {
	Package osvPackage `json:"package"`
	Version string     `json:"version,omitempty"`
}

type osvPackage struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}

type osvBatchRequest struct {
	Queries []osvQuery `json:"queries"`
}

// Resolve returns vulns for a package using the cache with stale-while-revalidate.
// Returns (vulns, ok). ok is false on network failure with no cache.
func (c *Client) Resolve(pkg Package) (vulns []Vuln, ok bool) {
	cached, fresh, found := loadCache(pkg)
	if found && fresh {
		return cached, true
	}

	// Need to fetch. Use a per-call budget.
	ctx, cancel := context.WithTimeout(context.Background(), totalBudget)
	defer cancel()
	fetched, err := c.queryOne(ctx, pkg, totalBudget)
	if err != nil {
		// Network failed. Use stale cache if we have any (stale-while-revalidate).
		if found {
			return cached, true
		}
		return nil, false
	}
	saveCache(pkg, fetched)
	return fetched, true
}

// CheckAll resolves CVEs for all packages, using cache and stopping early if offline.
func (c *Client) CheckAll(pkgs []Package) (results []Result, ok bool) {
	if len(pkgs) == 0 {
		return nil, true
	}
	for i, pkg := range pkgs {
		vulns, networkOK := c.Resolve(pkg)
		if !networkOK && i == 0 {
			// First package failed with no cache: assume offline, stop.
			return results, false
		}
		if len(vulns) > 0 {
			results = append(results, Result{Package: pkg, Vulns: vulns})
		}
	}
	return results, true
}

func (c *Client) queryOne(ctx context.Context, pkg Package, budget time.Duration) ([]Vuln, error) {
	reqBody := osvQuery{
		Package: osvPackage{Name: pkg.Name, Ecosystem: pkg.Ecosystem},
		Version: pkg.Version,
	}
	body, err := json.Marshal(reqBody)
	if err != nil {
		return nil, err
	}

	callCtx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()

	req, err := http.NewRequestWithContext(callCtx, http.MethodPost, osvSingleURL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("osv returned status %d", resp.StatusCode)
	}

	var parsed struct {
		Vulns []struct {
			ID       string `json:"id"`
			Summary  string `json:"summary"`
			Details  string `json:"details"`
			Severity []struct {
				Type  string `json:"type"`
				Score string `json:"score"`
			} `json:"severity"`
			Affected []struct {
				Ranges []struct {
					Events []struct {
						Fixed string `json:"fixed"`
					} `json:"events"`
				} `json:"ranges"`
			} `json:"affected"`
		} `json:"vulns"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return nil, err
	}

	var vulns []Vuln
	for _, v := range parsed.Vulns {
		vuln := Vuln{
			ID:      v.ID,
			Summary: v.Summary,
			CVSS:    extractCVSS(v.Severity),
		}
		vuln.FixedVersion = extractFixedVersion(v.Affected)
		vulns = append(vulns, vuln)
	}
	return vulns, nil
}

// extractCVSS pulls a numeric CVSS base score from OSV severity entries.
// OSV gives CVSS vector strings; we parse the base score if present, else 0.
func extractCVSS(sev []struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}) float64 {
	for _, s := range sev {
		// Score is a CVSS vector like "CVSS:3.1/AV:N/.../...". We cannot fully
		// parse the vector cheaply, so look for a trailing numeric base score
		// if the API provides one; otherwise return 0 and let the caller default.
		if f := parseLeadingFloat(s.Score); f > 0 {
			return f
		}
	}
	return 0
}

// parseLeadingFloat tries to read a float like "9.6" from a string. OSV severity
// score is usually a vector, not a number, so this often returns 0. That is fine;
// severity then defaults based on presence of any CVE.
func parseLeadingFloat(s string) float64 {
	s = strings.TrimSpace(s)
	var f float64
	if _, err := fmt.Sscanf(s, "%f", &f); err == nil {
		return f
	}
	return 0
}

func extractFixedVersion(affected []struct {
	Ranges []struct {
		Events []struct {
			Fixed string `json:"fixed"`
		} `json:"events"`
	} `json:"ranges"`
}) string {
	for _, a := range affected {
		for _, r := range a.Ranges {
			for _, e := range r.Events {
				if e.Fixed != "" {
					return e.Fixed
				}
			}
		}
	}
	return ""
}
