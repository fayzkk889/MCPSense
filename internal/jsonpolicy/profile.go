package jsonpolicy

import (
	"crypto/sha256"
	_ "embed"
	"fmt"
)

//go:embed json.go
var policySource string

// Profile invalidates saved verification identity when input interpretation changes.
func Profile() string { return fmt.Sprintf("%x", sha256.Sum256([]byte(policySource))) }
