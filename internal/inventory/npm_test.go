package inventory

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/fayzkk889/MCPSense/internal/models"
)

func descriptor(name, version string) map[string]interface{} {
	base := name[strings.LastIndex(name, "/")+1:]
	return map[string]interface{}{"version": version, "resolved": "https://registry.npmjs.org/" + name + "/-/" + base + "-" + version + ".tgz"}
}

func TestNestedVersionsAliasesAndAllDependencyClasses(t *testing.T) {
	pkgs := map[string]interface{}{"": map[string]interface{}{"name": "local-project"}}
	pkgs["node_modules/lodash"] = descriptor("lodash", "4.17.20")
	pkgs["node_modules/parent/node_modules/lodash"] = descriptor("lodash", "4.17.21")
	alias := descriptor("@modelcontextprotocol/sdk", "1.31.0")
	alias["name"] = "@modelcontextprotocol/sdk"
	alias["dev"] = true
	pkgs["node_modules/sdk-alias"] = alias
	optional := descriptor("optional", "1.0.0")
	optional["optional"] = true
	pkgs["node_modules/optional"] = optional
	for _, version := range []int{2, 3} {
		b, _ := json.Marshal(map[string]interface{}{"lockfileVersion": version, "packages": pkgs})
		inv, err := ParseNPM(b, "selected-lock.json")
		if err != nil || len(inv.Packages) != 4 || len(inv.SHA256) != 64 {
			t.Fatalf("inventory: %+v %v", inv, err)
		}
		got, err := Packages(inv)
		if err != nil || len(got) != 4 {
			t.Fatalf("packages: %v %v", got, err)
		}
		if got[0].Name != "lodash" || got[1].Name != "optional" || got[2].Version != "4.17.21" || got[3].Name != "@modelcontextprotocol/sdk" {
			t.Fatalf("wrong identities/order: %v", got)
		}
	}
}

func TestUnsupportedIdentitiesNeverBecomePublicQueries(t *testing.T) {
	for _, tc := range []struct {
		name  string
		entry map[string]interface{}
	}{
		{"link", map[string]interface{}{"link": true, "resolved": "../local"}},
		{"git", map[string]interface{}{"version": "1.0.0", "resolved": "git+https://example.invalid/repo#abc"}},
		{"private", map[string]interface{}{"version": "1.0.0", "resolved": "https://user:secret@example.invalid/x.tgz"}},
		{"missing-source", map[string]interface{}{"version": "1.0.0"}},
		{"range", descriptor("fixture", "^1.0.0")},
		{"tag", descriptor("fixture", "latest")},
		{"wrong-tarball", descriptor("other", "1.0.0")},
		{"prerelease-leading-zero", descriptor("fixture", "1.0.0-01")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b, _ := json.Marshal(map[string]interface{}{"lockfileVersion": 3, "packages": map[string]interface{}{"node_modules/fixture": tc.entry}})
			inv, err := ParseNPM(b, "lock.json")
			if err != nil {
				t.Fatal(err)
			}
			if inv.Packages[0].Unresolved == "" {
				t.Fatalf("guessed identity: %+v", inv)
			}
			if _, err := Packages(inv); err == nil {
				t.Fatal("partial inventory accepted")
			}
			out, _ := json.Marshal(inv)
			if strings.Contains(string(out), "secret") || strings.Contains(string(out), "example.invalid") {
				t.Fatal("source credentials leaked")
			}
		})
	}
}

func TestMalformedAndAmbiguousLockfiles(t *testing.T) {
	for _, b := range []string{
		`null`, `[]`, `{}`, `{"lockfileVersion":1,"dependencies":{}}`,
		`{"lockfileVersion":3,"packages":null}`, `{"lockfileVersion":3,"packages":{"node_modules/x":null}}`,
		`{"lockfileVersion":3,"packages":{},"packages":{}}`,
		`{"lockfileVersion":3,"packages":{"node_modules/x":{"version":"1.0.0","version":"2.0.0"}}}`,
		`{"lockfileVersion":3,"packages":{}} {}`, `{"lockfileVersion":3,"packages":{}}garbage`,
		strings.Repeat("[", 66) + strings.Repeat("]", 66), strings.Repeat(" ", (4<<20)+1),
	} {
		if _, err := ParseNPM([]byte(b), "lock.json"); err == nil {
			t.Fatalf("accepted malformed input: %.100s", b)
		}
	}
}

func TestNPMKeysAreCaseSensitive(t *testing.T) {
	b := []byte(`{"lockfileVersion":3,"packages":{"node_modules/lodash":{"version":"4.17.20","Version":"4.17.21","resolved":"https://registry.npmjs.org/lodash/-/lodash-4.17.20.tgz"}},"Packages":{}}`)
	inv, err := ParseNPM(b, "lock.json")
	if err != nil || len(inv.Packages) != 1 || inv.Packages[0].Version != "4.17.20" {
		t.Fatalf("case-folded keys replaced inventory: %+v %v", inv, err)
	}
}

func TestDistinctQueryLimitAndRepeatedLocations(t *testing.T) {
	inv := &models.DependencyInventory{}
	for i := 0; i < 2049; i++ {
		inv.Packages = append(inv.Packages, models.Dependency{Name: fmt.Sprint("p", i), Version: "1.0.0", Ecosystem: "npm", Path: fmt.Sprint(i)})
	}
	if _, err := Packages(inv); err == nil {
		t.Fatal("unbounded query inventory")
	}
	for i := range inv.Packages {
		inv.Packages[i].Name = "one"
	}
	if pkgs, err := Packages(inv); err != nil || len(pkgs) != 2049 {
		t.Fatalf("repeated locations lost: %d %v", len(pkgs), err)
	}
}

func FuzzNPMNeverPanics(f *testing.F) {
	f.Add([]byte(`{"lockfileVersion":3,"packages":{}}`))
	f.Fuzz(func(t *testing.T, b []byte) { _, _ = ParseNPM(b, "fuzz.json") })
}
