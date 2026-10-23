package checks

import (
	"testing"

	"github.com/fayzkk889/MCPSense/internal/models"
)

func TestPrimaryLaunchPackageIdentity(t *testing.T) {
	for _, tc := range []struct {
		name, command           string
		args                    []string
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
			if tc.pkg == "" {
				if len(pkgs) != 0 {
					t.Fatalf("invented registry identity: %+v", pkgs)
				}
				return
			}
			if len(pkgs) != 1 || pkgs[0].Name != tc.pkg || pkgs[0].Version != tc.version || pkgs[0].Ecosystem != tc.ecosystem {
				t.Fatalf("wrong advisory identity: %+v", pkgs)
			}
		})
	}
}

func TestUnrelatedArgumentCannotPinPrimaryPackage(t *testing.T) {
	ctx := newTestCtx()
	ctx.ClientConfig = &models.MCPClientConfig{MCPServers: map[string]models.MCPServerEntry{"fixture": {Command: "npx", Args: []string{"-y", "@scope/server", "--label", "example@1.2.3"}}}}
	if len((&ConfigUnverifiedSourceCheck{}).Run(ctx)) == 0 {
		t.Fatal("unrelated later argument hid unpinned primary package")
	}
}

func TestLaunchGrammarBoundaries(t *testing.T) {
	for _, tc := range []struct {
		command       string
		args          []string
		name, version string
	}{
		{"npx", []string{"--cache", "/tmp/npm-cache", "-y", "@scope/server@1.2.3"}, "@scope/server", "1.2.3"},
		{"npx", []string{"-y", "@scope/server@latest"}, "@scope/server", ""},
		{"npx", []string{"-y", "@scope/server@^1.2.3"}, "@scope/server", ""},
		{"npx", []string{"-y", "@scope/server", "--package=unrelated@1.2.3"}, "@scope/server", ""},
		{"npm", []string{"exec", "@scope/command", "--package=@scope/server@1.2.3"}, "@scope/server", "1.2.3"},
		{"npm", []string{"exec", "--", "@scope/server@1.2.3", "--package=unrelated"}, "@scope/server", "1.2.3"},
		{"uv", []string{"tool", "run", "--from", "server[extra]==1.2.3", "command"}, "server", "1.2.3"},
		{"pipx", []string{"run", "--spec", "server==1.2.3", "command"}, "server", "1.2.3"},
		{"npx", []string{"--unknown-value-option", "not-a-package", "@scope/server"}, "", ""},
		{"uvx", []string{"--from", "git+https://example.invalid/repo@v1", "server"}, "", ""},
		{"uvx", []string{"--from"}, "", ""},
		{"npx", []string{"./local.js"}, "", ""},
		{"npm", []string{"run", "start"}, "", ""},
	} {
		pkgs := extractPackages(&models.MCPClientConfig{MCPServers: map[string]models.MCPServerEntry{"fixture": {Command: tc.command, Args: tc.args}}})
		if tc.name == "" {
			if len(pkgs) != 0 {
				t.Fatalf("invented package for %v: %+v", tc.args, pkgs)
			}
			continue
		}
		if len(pkgs) != 1 || pkgs[0].Name != tc.name || pkgs[0].Version != tc.version {
			t.Fatalf("wrong identity for %v: %+v", tc.args, pkgs)
		}
	}
}

func TestActualVersionPinsAndMultipleExplicitPackages(t *testing.T) {
	for _, spec := range []string{"@scope/server", "@scope/server@latest", "@scope/server@^1.2.3", "@scope/server@*"} {
		ctx := newTestCtx()
		ctx.ClientConfig = &models.MCPClientConfig{MCPServers: map[string]models.MCPServerEntry{"fixture": {Command: "npx", Args: []string{"-y", spec}}}}
		if len((&ConfigUnverifiedSourceCheck{}).Run(ctx)) != 1 {
			t.Fatalf("moving version not flagged: %s", spec)
		}
	}
	ctx := newTestCtx()
	ctx.ClientConfig = &models.MCPClientConfig{MCPServers: map[string]models.MCPServerEntry{"fixture": {Command: "npm", Args: []string{"exec", "--yes", "--package=@scope/first@1.2.3", "--package=@scope/second@2.3.4", "--package=@scope/first@1.2.3", "--", "command"}}}}
	pkgs := extractPackages(ctx.ClientConfig)
	if len(pkgs) != 2 || pkgs[0].Name != "@scope/first" || pkgs[1].Name != "@scope/second" {
		t.Fatalf("multiple packages lost or duplicated: %+v", pkgs)
	}
	if len((&ConfigUnverifiedSourceCheck{}).Run(ctx)) != 0 {
		t.Fatal("exact versions flagged as unpinned")
	}
}
