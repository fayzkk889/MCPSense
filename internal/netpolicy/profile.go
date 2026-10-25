package netpolicy

import (
	"embed"
	"github.com/fayzkk889/MCPSense/internal/detection"
)

//go:embed address.go profile.go
var sources embed.FS

func Profile() string { return detection.SourceDigest(sources) }
