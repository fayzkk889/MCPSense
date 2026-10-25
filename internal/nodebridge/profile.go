package nodebridge

import (
	"embed"
	"github.com/fayzkk889/MCPSense/internal/detection"
)

//go:embed profile.go paths_native.go bridge_js.go http_js.go node.cjs
var sources embed.FS

// Profile covers the trusted Node host implementation as well as its Go bridge.
func Profile() string { return detection.SourceDigest(sources) }
