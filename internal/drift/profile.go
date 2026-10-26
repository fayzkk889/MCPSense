package drift

import (
	"embed"

	"github.com/fayzkk889/MCPSense/internal/detection"
)

// Changes in baseline comparisons must invalidate detector equivalence too.
//
//go:embed drift.go metadata.go store.go profile.go required.go
var driftSources embed.FS

func Profile() string { return detection.SourceDigest(driftSources) }
