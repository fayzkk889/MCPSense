// Package inventory reads bounded, explicitly selected dependency declarations.
package inventory

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/url"
	"path"
	"regexp"
	"sort"
	"strings"

	"github.com/fayzkk889/MCPSense/internal/cve"
	"github.com/fayzkk889/MCPSense/internal/models"
	"github.com/fayzkk889/MCPSense/internal/utils"
)

var npmName = regexp.MustCompile(`^(?:@[a-z0-9_][a-z0-9._-]*/)?[a-z0-9_][a-z0-9._-]*$`)
var npmVersion = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$`)

func ReadNPM(file string) (*models.DependencyInventory, error) {
	b, err := utils.ReadInput(file)
	if err != nil {
		return nil, err
	}
	return ParseNPM(b, file)
}

func ParseNPM(b []byte, file string) (*models.DependencyInventory, error) {
	if len(b) > utils.MaxInputBytes {
		return nil, fmt.Errorf("dependency input exceeds file limit")
	}
	digest := models.HashIdentity(string(b))
	b = bytes.TrimPrefix(b, []byte{0xef, 0xbb, 0xbf})
	if err := uniqueJSON(b); err != nil {
		return nil, err
	}
	// npm's JSON keys are case-sensitive; Go struct decoding is not. Read
	// exact keys so a second differently cased field cannot replace evidence.
	var raw map[string]json.RawMessage
	var version int
	var packages map[string]json.RawMessage
	if json.Unmarshal(b, &raw) != nil || raw == nil || json.Unmarshal(raw["lockfileVersion"], &version) != nil || json.Unmarshal(raw["packages"], &packages) != nil || (version != 2 && version != 3) || packages == nil {
		return nil, fmt.Errorf("dependencies mode requires an npm v2/v3 package-lock or shrinkwrap with a packages map; package.json ranges and v1 lockfiles are unsupported")
	}
	if len(packages) > 10001 {
		return nil, fmt.Errorf("dependency entry count exceeds 10000")
	}
	inv := &models.DependencyInventory{Format: fmt.Sprintf("npm-lock-v%d", version), Input: file, SHA256: digest, Packages: []models.Dependency{}}
	paths := []string{}
	for p := range packages {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	for _, p := range paths {
		var item struct {
			Name     string `json:"name"`
			Version  string `json:"version"`
			Resolved string `json:"resolved"`
			Link     bool   `json:"link"`
		}
		var fields map[string]json.RawMessage
		if json.Unmarshal(packages[p], &fields) != nil || fields == nil {
			return nil, fmt.Errorf("invalid npm dependency descriptor")
		}
		for key, dest := range map[string]interface{}{"name": &item.Name, "version": &item.Version, "resolved": &item.Resolved, "link": &item.Link} {
			if value, exists := fields[key]; exists && json.Unmarshal(value, dest) != nil {
				return nil, fmt.Errorf("invalid npm dependency descriptor field")
			}
		}
		if p == "" {
			continue
		}
		dep := models.Dependency{Path: p}
		name := item.Name
		if name == "" {
			name = locationName(p)
		}
		switch {
		case item.Link || !strings.Contains("/"+p, "/node_modules/"):
			dep.Unresolved = "local_or_workspace_dependency"
		case !validLocation(p):
			dep.Unresolved = "unsupported_dependency_path"
		case !npmName.MatchString(name) || len(name) > 214:
			dep.Unresolved = "unsupported_package_identity"
		case !exactVersion(item.Version):
			dep.Unresolved = "unresolved_version"
		case !registrySource(item.Resolved, name, item.Version):
			dep.Unresolved = "unverified_registry_source"
		default:
			dep.Name, dep.Version, dep.Ecosystem = name, item.Version, "npm"
		}
		inv.Packages = append(inv.Packages, dep)
	}
	missing := map[string]bool{}
	for _, p := range paths {
		if p != "" && !validLocation(p) {
			continue
		}
		var fields map[string]json.RawMessage
		_ = json.Unmarshal(packages[p], &fields) // descriptor shape was validated above
		var required, optional map[string]string
		for key, dest := range map[string]*map[string]string{"dependencies": &required, "optionalDependencies": &optional} {
			if value, exists := fields[key]; exists && json.Unmarshal(value, dest) != nil {
				return nil, fmt.Errorf("invalid npm dependency reference map")
			}
		}
		for name := range required {
			if !npmName.MatchString(name) || len(name) > 214 {
				return nil, fmt.Errorf("unsupported npm dependency reference name")
			}
			if _, isOptional := optional[name]; isOptional {
				continue
			}
			if !hasDependency(packages, p, name) {
				location := path.Join(p, "node_modules", name)
				if !missing[location] {
					missing[location] = true
					inv.Packages = append(inv.Packages, models.Dependency{Path: location, Unresolved: "missing_required_dependency"})
					if len(inv.Packages) > 10000 {
						return nil, fmt.Errorf("dependency entry count exceeds 10000")
					}
				}
			}
		}
	}
	if len(inv.Packages) > 10000 {
		return nil, fmt.Errorf("dependency entry count exceeds 10000")
	}
	sort.Slice(inv.Packages, func(i, j int) bool { return inv.Packages[i].Path < inv.Packages[j].Path })
	return inv, nil
}

func hasDependency(packages map[string]json.RawMessage, parent, name string) bool {
	for {
		if path.Base(parent) != "node_modules" {
			if _, exists := packages[path.Join(parent, "node_modules", name)]; exists {
				return true
			}
		}
		if parent == "" || parent == "." {
			return false
		}
		next := path.Dir(parent)
		if next == parent {
			return false
		}
		parent = next
	}
}

func validLocation(p string) bool {
	return len(p) <= 4096 && strings.Count(p, "/") <= 64 && path.Clean(p) == p && !strings.ContainsAny(p, "\\\x00\r\n") && !strings.HasPrefix(p, "/") && p != ".." && !strings.HasPrefix(p, "../")
}

func locationName(p string) string {
	i := strings.LastIndex("/"+p, "/node_modules/")
	if i < 0 {
		return ""
	}
	return ("/" + p)[i+len("/node_modules/"):]
}

func exactVersion(s string) bool {
	m := npmVersion.FindStringSubmatch(s)
	if m == nil || len(s) > 256 {
		return false
	}
	for _, id := range strings.Split(m[4], ".") {
		if len(id) > 1 && id[0] == '0' && strings.Trim(id, "0123456789") == "" {
			return false
		}
	}
	return true
}

func registrySource(source, name, version string) bool {
	u, err := url.Parse(source)
	if err != nil || u.Scheme != "https" || u.Host != "registry.npmjs.org" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return false
	}
	return u.Path == "/"+name+"/-/"+path.Base(name)+"-"+version+".tgz"
}

// Packages refuses incomplete inventories before any advisory traffic starts.
func Packages(inv *models.DependencyInventory) ([]cve.Package, error) {
	pkgs := []cve.Package{}
	seen := map[string]bool{}
	for _, dep := range inv.Packages {
		if dep.Unresolved != "" {
			return nil, fmt.Errorf("dependency inventory contains unresolved identities; inspect with --offline and review unsupported sources, workspaces or versions before querying advisories")
		}
		key := dep.Name + "@" + dep.Version
		seen[key] = true
		pkgs = append(pkgs, cve.Package{Name: dep.Name, Version: dep.Version, Ecosystem: dep.Ecosystem, Server: dep.Path, File: inv.Input})
	}
	if len(seen) > cve.MaxPackages {
		return nil, fmt.Errorf("dependency inventory exceeds %d distinct advisory queries", cve.MaxPackages)
	}
	return pkgs, nil
}

// Duplicate object keys are ambiguous security input. Bound recursive validation
// before decoding maps, which otherwise silently retain only the last value.
func uniqueJSON(b []byte) error {
	d := json.NewDecoder(bytes.NewReader(b))
	var visit func(int) error
	visit = func(depth int) error {
		if depth > 64 {
			return fmt.Errorf("dependency JSON nesting exceeds limit")
		}
		tok, err := d.Token()
		if err != nil {
			return fmt.Errorf("invalid dependency JSON")
		}
		delim, ok := tok.(json.Delim)
		if !ok {
			return nil
		}
		keys := map[string]bool{}
		for d.More() {
			if delim == '{' {
				k, e := d.Token()
				key, valid := k.(string)
				if e != nil || !valid || keys[key] {
					return fmt.Errorf("duplicate or invalid dependency JSON key")
				}
				keys[key] = true
			}
			if err := visit(depth + 1); err != nil {
				return err
			}
		}
		_, err = d.Token()
		return err
	}
	if err := visit(0); err != nil {
		return err
	}
	if d.More() {
		return fmt.Errorf("trailing dependency JSON")
	}
	return nil
}
