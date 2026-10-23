package cve

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	osvSingleURL = "https://api.osv.dev/v1/query"
	// Total network budget for the whole CVE phase.
	totalBudget = 30 * time.Second
	callBudget  = 5 * time.Second
	MaxPackages = 2048
	maxWorkers  = 8
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
	Source       string
	ReviewedAt   string
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
	http *http.Client
}

type responseBudgetKey struct{}

func consumeBudget(ctx context.Context, size int) bool {
	if used, ok := ctx.Value(responseBudgetKey{}).(*atomic.Int64); ok {
		return used.Add(int64(size)) <= 64<<20
	}
	return true
}

func NewClient() *Client {
	return &Client{
		http: &http.Client{Timeout: callBudget, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
	}
}

type osvQuery struct {
	Package   osvPackage `json:"package"`
	Version   string     `json:"version,omitempty"`
	PageToken string     `json:"page_token,omitempty"`
}

type osvPackage struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}

// Resolve returns vulns for a package using the cache with stale-while-revalidate.
// Returns (vulns, ok). ok is false on network failure with no cache.
func (c *Client) Resolve(pkg Package) (vulns []Vuln, ok bool) {
	ctx, cancel := context.WithTimeout(context.Background(), totalBudget)
	defer cancel()
	return c.resolve(ctx, pkg)
}
func (c *Client) resolve(ctx context.Context, pkg Package) (vulns []Vuln, ok bool) {
	if ctx.Err() != nil {
		return nil, false
	}
	cached, fresh, found := loadCache(pkg)
	if found && fresh {
		size := 0
		for _, v := range cached {
			size += 128 + len(v.ID) + len(v.Summary) + len(v.FixedVersion) + len(v.Source) + len(v.ReviewedAt)
		}
		if !consumeBudget(ctx, size) {
			return nil, false
		}
		return cached, true
	}

	// Need to fetch. Use a per-call budget.
	fetched, err := c.queryOne(ctx, pkg, callBudget)
	if err != nil {
		// Network failed. Use stale cache if we have any (stale-while-revalidate).
		if found {
			return cached, false
		}
		return nil, false
	}
	saveCache(pkg, fetched)
	return fetched, true
}

// CheckAll resolves CVEs with bounded concurrency, preserving input order and locations.
func (c *Client) CheckAll(pkgs []Package) (results []Result, ok bool) {
	return c.CheckAllContext(context.Background(), pkgs)
}

func (c *Client) CheckAllContext(parent context.Context, pkgs []Package) (results []Result, ok bool) {
	if len(pkgs) > 10000 {
		return nil, false
	}
	ctx, cancel := context.WithTimeout(parent, totalBudget)
	defer cancel()
	ctx = context.WithValue(ctx, responseBudgetKey{}, new(atomic.Int64))
	unique := []Package{}
	indexes := make(map[string]int)
	for _, pkg := range pkgs {
		key := cacheKey(pkg)
		if _, exists := indexes[key]; !exists {
			indexes[key] = len(unique)
			unique = append(unique, pkg)
		}
	}
	if len(unique) > MaxPackages || ctx.Err() != nil {
		return nil, false
	}
	vulns := make([][]Vuln, len(unique))
	completed := make([]bool, len(unique))
	jobs := make(chan int)
	var workers sync.WaitGroup
	for n := 0; n < maxWorkers && n < len(unique); n++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for i := range jobs {
				vulns[i], completed[i] = c.resolve(ctx, unique[i])
				if !completed[i] {
					cancel()
				}
			}
		}()
	}
	for i := range unique {
		select {
		case jobs <- i:
		case <-ctx.Done():
			close(jobs)
			workers.Wait()
			return nil, false
		}
	}
	close(jobs)
	workers.Wait()
	for _, complete := range completed {
		if !complete {
			return nil, false
		}
	}
	if ctx.Err() != nil {
		return nil, false
	}
	for _, pkg := range pkgs {
		found := vulns[indexes[cacheKey(pkg)]]
		if len(found) > 0 {
			results = append(results, Result{Package: pkg, Vulns: found})
		}
	}
	return results, true
}

func (c *Client) queryOne(ctx context.Context, pkg Package, budget time.Duration) ([]Vuln, error) {
	reqBody := osvQuery{
		Package: osvPackage{Name: pkg.Name, Ecosystem: pkg.Ecosystem},
		Version: pkg.Version,
	}
	var all []Vuln
	seenTokens := map[string]bool{}
	seenIDs := map[string]bool{}
	totalBytes := 0
	for page := 0; page < 32; page++ {
		body, err := json.Marshal(reqBody)
		if err != nil {
			return nil, err
		}

		callCtx, cancel := context.WithTimeout(ctx, budget)

		req, err := http.NewRequestWithContext(callCtx, http.MethodPost, osvSingleURL, bytes.NewReader(body))
		if err != nil {
			cancel()
			return nil, err
		}
		req.Header.Set("Content-Type", "application/json")

		resp, err := c.http.Do(req)
		if err != nil {
			cancel()
			return nil, err
		}

		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			cancel()
			return nil, fmt.Errorf("osv returned status %d", resp.StatusCode)
		}

		var parsed struct {
			NextPageToken string `json:"next_page_token"`
			Vulns         []struct {
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
		data, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20+1))
		resp.Body.Close()
		cancel()
		if err != nil {
			return nil, err
		}
		if len(data) > 4<<20 {
			return nil, fmt.Errorf("OSV response exceeds size limit")
		}
		if !consumeBudget(ctx, len(data)) {
			return nil, fmt.Errorf("OSV scan response byte budget exceeded")
		}
		totalBytes += len(data)
		if totalBytes > 16<<20 {
			return nil, fmt.Errorf("OSV pagination exceeds byte budget")
		}
		var shape map[string]json.RawMessage
		if json.Unmarshal(data, &shape) != nil || shape == nil || shape["error"] != nil {
			return nil, fmt.Errorf("invalid OSV response object")
		}
		if err := json.Unmarshal(data, &parsed); err != nil {
			return nil, err
		}

		for _, v := range parsed.Vulns {
			if v.ID == "" {
				return nil, fmt.Errorf("OSV returned an advisory without an ID")
			}
			if seenIDs[v.ID] {
				continue
			}
			seenIDs[v.ID] = true
			vuln := Vuln{
				ID:      v.ID,
				Summary: v.Summary,
				CVSS:    extractCVSS(v.Severity),
			}
			vuln.FixedVersion = extractFixedVersion(v.Affected)
			all = append(all, vuln)
			if len(all) > 16384 {
				return nil, fmt.Errorf("OSV advisory count exceeds limit")
			}
		}
		if parsed.NextPageToken == "" {
			return all, nil
		}
		if seenTokens[parsed.NextPageToken] || len(parsed.NextPageToken) > 8192 {
			return nil, fmt.Errorf("invalid OSV pagination token")
		}
		seenTokens[parsed.NextPageToken] = true
		reqBody.PageToken = parsed.NextPageToken
	}
	return nil, fmt.Errorf("OSV pagination exceeds page limit")
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
