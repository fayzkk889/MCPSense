package models

// DependencyInventory describes declarations read from an explicitly selected
// lockfile. It is not an attestation of installed or executing code.
type DependencyInventory struct {
	Format   string       `json:"format"`
	Input    string       `json:"input"`
	SHA256   string       `json:"sha256"`
	Packages []Dependency `json:"packages"`
}

type Dependency struct {
	Path       string `json:"path"`
	Name       string `json:"name,omitempty"`
	Version    string `json:"version,omitempty"`
	Ecosystem  string `json:"ecosystem,omitempty"`
	Unresolved string `json:"unresolved,omitempty"`
}
