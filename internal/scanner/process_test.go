package scanner

import (
	"os"
	"strings"
	"testing"
	"time"
)

func TestSilentMCPHelper(t *testing.T) {
	if len(os.Args) > 0 && os.Args[len(os.Args)-1] == "MCPSENSE_SILENT_FIXTURE" {
		time.Sleep(time.Minute)
		os.Exit(0)
	}
}
func TestAuthorizedStdioTimeout(t *testing.T) {
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	_, _, err = New(Options{Mode: ModeLive, AllowExec: true, Protocol: "legacy", Timeout: 500 * time.Millisecond, ServerArgs: []string{"-test.run=TestSilentMCPHelper", "--", "MCPSENSE_SILENT_FIXTURE"}}).Scan(binary)
	if err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("timeout not propagated: %v", err)
	}
	if time.Since(start) > 5*time.Second {
		t.Fatal("authorized process was not promptly cleaned up")
	}
}
