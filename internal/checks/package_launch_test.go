package checks

import (
	"testing"

	"github.com/fayzkk889/MCPSense/internal/models"
)

func TestPrimaryLaunchPackageIdentity(t *testing.T) {
	for _, tc := range []struct {
		name, command string
		args []string
		pkg, version, ecosystem string
	}{
		{"pypi exact pin", "uvx", []string{"awslabs.postgres-mcp-server==1.1.6"}, "awslabs.postgres-mcp-server", "1.1.6", "PyPI"},
		{"pypi from", "uvx", []string{"--from", "awslabs.postgres-mcp-server==1.1.6", "awslabs.postgres-mcp-server"}, "awslabs.postgres-mcp-server", "1.1.6", "PyPI"},
		{"npm exec", "npm", []string{"exec", "--yes", "--package=@scope/server@1.2.3", "--", "server"}, "@scope/server", "1.2.3", "npm"},
		{"absolute launcher", `C:\tools\uvx.exe`, []string{"awslabs.postgres-mcp-server==1.1.6"}, "awslabs.postgres-mcp-server", "1.1.6", "PyPI"},
		{"local node script", "node", []string{"server.js"}, "", "", ""},
		{"python module", "python", []string{"-m", "server"}, "", "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pkgs := extractPackages(&models.MCPClientConfig{MCPServers: map[string]models.MCPServerEntry{"fixture": {Command: tc.command, Args: tc.args}}})
			if tc.pkg == "" { if len(pkgs) != 0 {t.Fatalf("invented registry identity: %+v", pkgs)}; return }
			if len(pkgs)!=1 || pkgs[0].Name!=tc.pkg || pkgs[0].Version!=tc.version || pkgs[0].Ecosystem!=tc.ecosystem {t.Fatalf("wrong advisory identity: %+v", pkgs)}
		})
	}
}

func TestUnrelatedArgumentCannotPinPrimaryPackage(t *testing.T) {
	ctx := newTestCtx()
	ctx.ClientConfig = &models.MCPClientConfig{MCPServers: map[string]models.MCPServerEntry{"fixture": {Command:"npx", Args:[]string{"-y", "@scope/server", "--label", "example@1.2.3"}}}}
	if len((&ConfigUnverifiedSourceCheck{}).Run(ctx)) == 0 {t.Fatal("unrelated later argument hid unpinned primary package")}
}
