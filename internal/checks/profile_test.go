package checks

import (
	"os"
	"strings"
	"testing"
)

func TestAllProductionCheckSourcesHaveIdentity(t *testing.T) {
	{
		entries, err := os.ReadDir(".")
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range entries {
			if strings.HasSuffix(entry.Name(), ".go") && !strings.HasSuffix(entry.Name(), "_test.go") {
				if _, err := checkSources.ReadFile(entry.Name()); err != nil {
					t.Fatalf("production source omitted from detector identity: %s", entry.Name())
				}
			}
		}
	}
	if len(DetectorProfile()) != 64 {
		t.Fatal("missing detector profile")
	}
}
