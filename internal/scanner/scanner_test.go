package scanner

import (
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/faizan/mcpsense/internal/models"
)

// testdataDir returns the absolute path to the testdata directory.
func testdataDir() string {
	_, filename, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(filename), "..", "..", "testdata")
}

func TestScanManifest_VulnerableServer(t *testing.T) {
	manifestPath := filepath.Join(testdataDir(), "vulnerable_server", "manifest.json")

	s := New(Options{Mode: ModeManifest})
	report, err := s.Scan(manifestPath)
	require.NoError(t, err)
	require.NotNil(t, report)

	assert.Equal(t, "manifest", report.ScanMode)
	assert.NotEmpty(t, report.Findings, "vulnerable manifest should produce findings")
	assert.Less(t, report.Score, 100, "score should be penalized")

	// Should detect injection in tool description.
	found := false
	for _, f := range report.Findings {
		if f.ID == "SEC-001" {
			found = true
			break
		}
	}
	assert.True(t, found, "should detect SEC-001 prompt injection")
}

func TestScanManifest_CompliantServer(t *testing.T) {
	manifestPath := filepath.Join(testdataDir(), "compliant_server", "manifest.json")

	s := New(Options{Mode: ModeManifest})
	report, err := s.Scan(manifestPath)
	require.NoError(t, err)
	require.NotNil(t, report)

	// No critical or high findings expected.
	for _, f := range report.Findings {
		assert.NotEqual(t, models.SeverityCritical, f.Severity,
			"compliant server should have no critical findings, got: %s - %s", f.ID, f.Title)
		assert.NotEqual(t, models.SeverityHigh, f.Severity,
			"compliant server should have no high findings, got: %s - %s", f.ID, f.Title)
	}
}

func TestScanStatic_VulnerableServer(t *testing.T) {
	dirPath := filepath.Join(testdataDir(), "vulnerable_server")

	s := New(Options{Mode: ModeStatic})
	report, err := s.Scan(dirPath)
	require.NoError(t, err)
	require.NotNil(t, report)

	assert.Equal(t, "static", report.ScanMode)
	assert.NotEmpty(t, report.Findings, "static scan of vulnerable server should produce findings")

	// Should find shell exec patterns.
	foundShellExec := false
	for _, f := range report.Findings {
		if f.ID == "SEC-002" || f.ID == "SEC-007" {
			foundShellExec = true
			break
		}
	}
	assert.True(t, foundShellExec, "should detect shell exec or command injection in vulnerable server source")
}

func TestScanStatic_CompliantServer(t *testing.T) {
	dirPath := filepath.Join(testdataDir(), "compliant_server")

	s := New(Options{Mode: ModeStatic})
	report, err := s.Scan(dirPath)
	require.NoError(t, err)
	require.NotNil(t, report)

	for _, f := range report.Findings {
		assert.NotEqual(t, models.SeverityCritical, f.Severity,
			"compliant server static scan should have no critical findings, got: %s", f.Title)
	}
}

func TestDetectMode(t *testing.T) {
	tests := []struct {
		target string
		want   ScanMode
	}{
		{"server.json", ModeManifest},
		{"mcp-config.json", ModeManifest},
		{"https://example.com/mcp", ModeLive},
		{"http://localhost:8080", ModeLive},
		{"./my-server --port 8080", ModeLive},
		{"/path/to/directory", ModeStatic},
		{"./server-dir", ModeLive}, // starts with ./
	}

	for _, tt := range tests {
		t.Run(tt.target, func(t *testing.T) {
			got := detectMode(tt.target)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestScanManifest_MissingAuth(t *testing.T) {
	manifestPath := filepath.Join(testdataDir(), "manifests", "missing_auth.json")

	s := New(Options{Mode: ModeManifest})
	report, err := s.Scan(manifestPath)
	require.NoError(t, err)

	found := false
	for _, f := range report.Findings {
		if f.ID == "SEC-005" {
			found = true
			break
		}
	}
	assert.True(t, found, "should detect missing auth finding")
}

func TestScanManifest_OverlyPermissive(t *testing.T) {
	manifestPath := filepath.Join(testdataDir(), "manifests", "overly_permissive.json")

	s := New(Options{Mode: ModeManifest})
	report, err := s.Scan(manifestPath)
	require.NoError(t, err)

	found := false
	for _, f := range report.Findings {
		if f.ID == "SEC-006" {
			found = true
			break
		}
	}
	assert.True(t, found, "should detect overly permissive resource scope")
}

func TestRunChecks_WithExclude(t *testing.T) {
	manifestPath := filepath.Join(testdataDir(), "vulnerable_server", "manifest.json")

	s := New(Options{Mode: ModeManifest, ExcludeIDs: []string{"SEC-001"}})
	report, err := s.Scan(manifestPath)
	require.NoError(t, err)

	for _, f := range report.Findings {
		assert.NotEqual(t, "SEC-001", f.ID, "excluded check should not appear in results")
	}
}
