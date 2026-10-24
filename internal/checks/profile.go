package checks

import (
	"crypto/sha256"
	"embed"
	"fmt"
	"github.com/fayzkk889/MCPSense/internal/cve"
	"github.com/fayzkk889/MCPSense/internal/detection"
	"github.com/fayzkk889/MCPSense/internal/drift"
	"github.com/fayzkk889/MCPSense/internal/inventory"
	"runtime"
)

// Keep the embedded production-file list complete when adding check code.
//
//go:embed config_security.go cve.go registry.go security.go skill.go spec_compliance.go tool_poisoning.go tool_quality.go profile.go metadata.go source_execution.go package_launch.go vendor_advisories.go
var checkSources embed.FS
var detectorProfile = fmt.Sprintf("%x", sha256.Sum256([]byte("mcpsense-detector-v1\x00"+runtime.Version()+"\x00"+detection.Profile()+"\x00"+drift.Profile()+"\x00"+cve.Profile()+"\x00"+inventory.Profile()+"\x00"+detection.SourceDigest(checkSources))))

func DetectorProfile() string { return detectorProfile }
