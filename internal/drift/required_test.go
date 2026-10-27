package drift

import (
	"testing"
	"time"

	"github.com/fayzkk889/MCPSense/internal/models"
)

func TestRequiredMetadataSnapshotRejectsUnknownChangesAndRemovals(t *testing.T) {
	m := &models.MCPManifest{Name: "records", Instructions: "Read the selected record.", Tools: []models.MCPTool{{Name: "read", Description: "Read one record."}}}
	before := BuildSnapshot(m, nil, "fixture", "manifest")
	current := BuildSnapshot(m, nil, "fixture", "manifest")
	current.CreatedAt = before.CreatedAt.Add(time.Hour)
	if err := RequireMetadataMatch(before, current); err != nil {
		t.Fatal(err)
	}
	m.Name = "different-server"
	if err := RequireMetadataMatch(before, BuildSnapshot(m, nil, "fixture", "manifest")); err == nil {
		t.Fatal("server identity change bypassed gate")
	}
	m.Name = "records"
	m.Instructions = "q7z αβγ unclassified new text"
	if err := RequireMetadataMatch(before, BuildSnapshot(m, nil, "fixture", "manifest")); err == nil {
		t.Fatal("unrecognized text bypassed the gate")
	}
	m.Instructions = "Read the selected record."
	m.Tools = nil
	if err := RequireMetadataMatch(before, BuildSnapshot(m, nil, "fixture", "manifest")); err == nil {
		t.Fatal("removed tool bypassed the gate")
	}
	before.Metadata = nil
	if err := RequireMetadataMatch(before, current); err == nil {
		t.Fatal("partial historical snapshot accepted")
	}
}
