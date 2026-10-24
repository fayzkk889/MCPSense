package cve

import (
	"embed"
	"github.com/fayzkk889/MCPSense/internal/detection"
)

//go:embed osv.go cache.go profile.go
var sources embed.FS

func Profile() string { return detection.SourceDigest(sources) }
