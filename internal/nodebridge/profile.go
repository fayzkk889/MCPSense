package nodebridge

import (
	"crypto/sha256"
	"embed"
	"fmt"
	"github.com/fayzkk889/MCPSense/internal/detection"
)

//go:embed profile.go paths_native.go bridge_js.go http_js.go node.cjs
var sources embed.FS

// Profile covers the trusted Node host implementation as well as its Go bridge.
func Profile() string { return detection.SourceDigest(sources) }

func HostSourceHash() string {
	b, _ := sources.ReadFile("node.cjs")
	return fmt.Sprintf("%x", sha256.Sum256(b))
}
