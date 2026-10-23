package checks

import (
	"path"
	"regexp"
	"sort"
	"strings"

	"github.com/fayzkk889/MCPSense/internal/cve"
	"github.com/fayzkk889/MCPSense/internal/models"
)

var npmPackageName = regexp.MustCompile(`^(?:@[a-zA-Z0-9_][a-zA-Z0-9._-]*/)?[a-zA-Z0-9_][a-zA-Z0-9._-]*$`)
var npmExactVersion = regexp.MustCompile(`^v?[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$`)
var pythonRequirement = regexp.MustCompile(`^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[A-Za-z0-9_,.-]+\])?(.*)$`)
var pythonExactVersion = regexp.MustCompile(`^[0-9][A-Za-z0-9.!+_-]*$`)

type packageLaunch struct {
	ecosystem          string
	specs              []string
	autoYes, shellCall bool
}

// Recognize a bounded set of package-launch grammars. Never infer a registry
// distribution from a local script/module or an unknown option's value.
func parsePackageLaunch(entry models.MCPServerEntry) packageLaunch {
	command := strings.ToLower(path.Base(strings.ReplaceAll(strings.TrimSpace(entry.Command), "\\", "/")))
	for _, ext := range []string{".exe", ".cmd", ".bat"} {
		command = strings.TrimSuffix(command, ext)
	}
	args := entry.Args
	var out packageLaunch
	npmExec := false
	switch command {
	case "npx":
		out.ecosystem = "npm"
	case "npm":
		if len(args) == 0 || (args[0] != "exec" && args[0] != "x") {
			return out
		}
		args = args[1:]
		out.ecosystem = "npm"
		npmExec = true
	case "uvx":
		out.ecosystem = "PyPI"
		out.autoYes = true
	case "uv":
		if len(args) < 2 || args[0] != "tool" || args[1] != "run" {
			return out
		}
		args = args[2:]
		out.ecosystem = "PyPI"
		out.autoYes = true
	case "pipx":
		if len(args) == 0 || args[0] != "run" {
			return out
		}
		args = args[1:]
		out.ecosystem = "PyPI"
		out.autoYes = true
	default:
		return out
	}
	var explicit []string
	positional := ""
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			if positional == "" && i+1 < len(args) {
				positional = args[i+1]
			}
			break
		}
		if !strings.HasPrefix(arg, "-") {
			if positional == "" {
				positional = arg
			}
			if !npmExec {
				break
			} // npx/uvx hand remaining arguments to the tool.
			continue
		}
		key, value, hasValue := strings.Cut(arg, "=")
		if (out.ecosystem == "npm" && (key == "--package" || key == "-p")) || (out.ecosystem == "PyPI" && (key == "--from" || key == "--spec")) {
			if !hasValue {
				i++
				if i >= len(args) {
					return packageLaunch{}
				}
				value = args[i]
			}
			explicit = append(explicit, value)
			continue
		}
		if out.ecosystem == "npm" && (key == "-c" || key == "--call") {
			out.shellCall = true
			if !hasValue {
				i++
				if i >= len(args) {
					return packageLaunch{}
				}
			}
			continue
		}
		if key == "-y" || key == "--yes" {
			out.autoYes = !hasValue || value == "true"
			continue
		}
		if key == "--no" || key == "--no-install" {
			out.autoYes = false
			continue
		}
		switch key {
		case "-q", "--quiet", "-v", "--verbose", "--offline", "--prefer-offline", "--prefer-online", "--isolated", "--no-progress", "--no-cache", "--ignore-existing":
			continue
		case "--cache", "--registry", "--userconfig", "--python", "--index-url", "--extra-index-url", "--index", "--default-index", "--directory", "--project", "--cwd":
			if !hasValue {
				i++
				if i >= len(args) {
					return packageLaunch{}
				}
			}
			continue
		default:
			// Unknown launcher syntax has no reliable registry identity.
			return packageLaunch{}
		}
	}
	if len(explicit) > 0 {
		out.specs = explicit
	} else if positional != "" && !out.shellCall {
		out.specs = []string{positional}
	}
	return out
}

func registryPackage(spec, ecosystem string) (name, version string) {
	if ecosystem == "npm" {
		name, version = splitPackageVersion(spec)
		if !npmPackageName.MatchString(name) {
			return "", ""
		}
		if !npmExactVersion.MatchString(version) {
			version = ""
		} else {
			version = strings.TrimPrefix(version, "v")
		}
		return
	}
	m := pythonRequirement.FindStringSubmatch(spec)
	if m == nil {
		return "", ""
	}
	name = m[1]
	rest := m[2]
	if rest == "" {
		return name, ""
	}
	if strings.HasPrefix(rest, "==") {
		version = strings.TrimPrefix(rest, "==")
	} else if strings.HasPrefix(rest, "@") {
		version = strings.TrimPrefix(rest, "@")
	} else {
		return "", ""
	}
	if !pythonExactVersion.MatchString(version) {
		return "", ""
	}
	return
}

func extractPackages(config *models.MCPClientConfig) []cve.Package {
	var pkgs []cve.Package
	names := make([]string, 0, len(config.MCPServers))
	for name := range config.MCPServers {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, server := range names {
		launch := parsePackageLaunch(config.MCPServers[server])
		seen := map[string]bool{}
		for _, spec := range launch.specs {
			name, version := registryPackage(spec, launch.ecosystem)
			if name == "" || seen[name+"@"+version] {
				continue
			}
			seen[name+"@"+version] = true
			pkgs = append(pkgs, cve.Package{Name: name, Version: version, Ecosystem: launch.ecosystem, Server: server})
		}
	}
	return pkgs
}
