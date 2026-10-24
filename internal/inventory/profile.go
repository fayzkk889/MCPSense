package inventory

import (
	"embed"
	"github.com/fayzkk889/MCPSense/internal/detection"
)

//go:embed npm.go profile.go
var sources embed.FS

func Profile() string { return detection.SourceDigest(sources) }
