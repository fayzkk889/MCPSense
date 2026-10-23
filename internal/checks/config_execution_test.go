package checks

import (
	"github.com/fayzkk889/MCPSense/internal/models"
	"testing"
)

func TestConfigExecutionEvidence(t *testing.T) {
	for _, tc := range []struct {
		name, command string
		args          []string
		want          bool
	}{
		{"literal data", "node", []string{"server.js", "--filter", `{ "status": "active" }`, "--label", "Research & Development"}, false},
		{"path substring", "C:\\tools\\sync\\server.exe", []string{"worker.js"}, false},
		{"shell named argument", "node", []string{"server.js", "--example", "bash -c example"}, false},
		{"normal script", "python3", []string{"server.py"}, false},
		{"windows file argument", "node", []string{"C:\\Work & Projects\\server.js"}, false},
		{"posix shell", "/bin/bash", []string{"-lc", "printf harmless"}, true},
		{"windows shell", "C:\\Windows\\System32\\cmd.exe", []string{"/c", "echo harmless"}, true},
		{"powershell code", "powershell.exe", []string{"-NoProfile", "-Command", "Write-Output harmless"}, true},
		{"inline code", "node", []string{"-e", "console.log('harmless')"}, true},
		{"legacy command string", "bash -c", []string{"printf harmless"}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := newTestCtx()
			ctx.ClientConfig = &models.MCPClientConfig{MCPServers: map[string]models.MCPServerEntry{"fixture": {Command: tc.command, Args: tc.args}}}
			findings := (&ConfigCommandInjectionCheck{}).Run(ctx)
			if (len(findings) > 0) != tc.want {
				t.Fatalf("want finding=%v got %+v", tc.want, findings)
			}
			for _, f := range findings {
				if f.Severity == models.SeverityCritical {
					t.Fatal("metadata alone asserted critical injection")
				}
			}
		})
	}
}
