package drift

import (
	"bytes"
	"encoding/json"
	"fmt"
	"time"
)

// RequireMetadataMatch is a deterministic, opt-in gate on the captured metadata
// inventory, including removals. It does not infer that a baseline was reviewed
// or authentic; its local file is an operator-controlled trust input. Runtime
// responses, process permissions and fields outside Snapshot remain out of scope.
func RequireMetadataMatch(before, current *Snapshot) error {
	if before == nil || current == nil || before.Metadata == nil || current.Metadata == nil || before.Metadata.CatalogHash == "" || current.Metadata.CatalogHash == "" || !supportedMetadata(before) || !supportedMetadata(current) {
		return fmt.Errorf("metadata baseline must include the full supported metadata snapshot; review the target and create one separately")
	}
	if before.Target != current.Target || before.Mode != current.Mode {
		return fmt.Errorf("metadata baseline target or mode differs")
	}
	left, right := *before, *current
	left.CreatedAt, right.CreatedAt = time.Time{}, time.Time{}
	previous, err := json.Marshal(left)
	if err != nil {
		return err
	}
	next, err := json.Marshal(right)
	if err != nil {
		return err
	}
	if !bytes.Equal(previous, next) {
		return fmt.Errorf("metadata baseline mismatch: advertised metadata changed; review it outside this gate and update the local baseline separately")
	}
	return nil
}
