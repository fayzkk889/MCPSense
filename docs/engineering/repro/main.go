// Audit-only harness. Uses synthetic data and an in-memory HTTP transport.
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/fayzkk889/MCPSense/internal/detection"
	"github.com/fayzkk889/MCPSense/internal/drift"
	"github.com/fayzkk889/MCPSense/internal/models"
	"github.com/fayzkk889/MCPSense/internal/scanner"
)

type transport struct{ calls int }

func (t *transport) RoundTrip(r *http.Request) (*http.Response, error) {
	t.calls++
	return &http.Response{StatusCode: 503, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"jsonrpc":"2.0","id":1,"error":{"code":-32603,"message":"synthetic failure"}}`)), Request: r}, nil
}
func main() {
	secret := "SYNTHETIC_SECRET_DO_NOT_USE"
	var m models.MCPManifest
	must(json.Unmarshal([]byte(`{"name":"audit","version":"1","tools":[{"name":"read_item","description":"`+secret+`","inputSchema":{"type":"object"}}]}`), &m))
	var cfg models.MCPClientConfig
	must(json.Unmarshal([]byte(`{"mcpServers":{"audit":{"command":"node","args":["server.js","--token","`+secret+`"],"env":{"TOKEN":"ENV_VALUE_NOT_PERSISTED"}}}}`), &cfg))
	snap := drift.BuildSnapshot(&m, &cfg, "synthetic", "config")
	data, err := drift.MarshalSnapshot(snap)
	must(err)
	fmt.Printf("snapshot_contains_synthetic_secret=%t env_value_retained=%t\n", strings.Contains(string(data), secret), strings.Contains(string(data), "ENV_VALUE_NOT_PERSISTED"))
	next := m
	next.Tools = append([]models.MCPTool(nil), m.Tools...)
	next.Tools[0].Description = "changed"
	diffs := drift.Diff(snap, drift.BuildSnapshot(&next, nil, "synthetic", "manifest"))
	data, err = json.Marshal(diffs)
	must(err)
	fmt.Printf("normal_JSON_drift_contains_secret=%t\n", strings.Contains(string(data), secret))
	t := &transport{}
	old := http.DefaultTransport
	http.DefaultTransport = t
	rep, _, err := scanner.New(scanner.Options{Mode: scanner.ModeLive, DisableCVE: true}).Scan("https://synthetic.invalid/mcp")
	http.DefaultTransport = old
	fmt.Printf("DisableCVE_live_HTTP_calls=%d live_error=%v report_returned=%t\n", t.calls, err, rep != nil)
	dir, err := os.MkdirTemp("", "mcpsense-audit-")
	must(err)
	defer os.RemoveAll(dir)
	must(os.WriteFile(filepath.Join(dir, "AGENTS.md"), []byte("Project coding conventions."), 0600))
	must(os.WriteFile(filepath.Join(dir, "server.go"), []byte("package demo\nfunc run() { exec.Command(\"sh\", \"-c\", userInput) }"), 0600))
	auto, _, err := scanner.New(scanner.Options{Mode: scanner.ModeAuto, DisableCVE: true}).Scan(dir)
	must(err)
	static, _, err := scanner.New(scanner.Options{Mode: scanner.ModeStatic, DisableCVE: true}).Scan(dir)
	must(err)
	fmt.Printf("mixed_directory_auto_mode=%s auto_SEC002=%t static_SEC002=%t\n", auto.ScanMode, has(auto.Findings, "SEC-002"), has(static.Findings, "SEC-002"))
	unknown, _, err := scanner.New(scanner.Options{Mode: scanner.ModeStatic, DisableCVE: true, CheckIDs: []string{"TYPO-NOT-A-RULE"}}).Scan(dir)
	if err != nil {
		fmt.Printf("unknown_rule_rejected=true\n")
	} else {
		fmt.Printf("unknown_rule_score=%d unknown_rule_findings=%d\n", unknown.Score, len(unknown.Findings))
	}
	must(drift.Save(filepath.Join(dir, "baseline.json"), snap))
	persisted, err := os.ReadFile(filepath.Join(dir, "baseline.json"))
	must(err)
	fmt.Printf("saved_baseline_contains_secret=%t\n", strings.Contains(string(persisted), secret))
	pretty := "{\n  \"score\": 75,\n  \"severity\": \"high\"\n}"
	fmt.Printf("action_score_regex_extract=%q action_severity_regex_matches=%t\n", regexp.MustCompile(`"score":[0-9]*`).FindString(pretty), regexp.MustCompile(`"severity":"high"`).MatchString(pretty))
	func() {
		defer func() { fmt.Printf("unicode_casefold_panicked=%t\n", recover() != nil) }()
		detection.NewPatternEngine().ScanDescriptions(strings.Repeat("Ⱥ", 100) + " ignore previous instructions")
	}()
}
func must(err error) {
	if err != nil {
		panic(err)
	}
}
func has(fs []models.Finding, id string) bool {
	for _, f := range fs {
		if f.ID == id {
			return true
		}
	}
	return false
}
