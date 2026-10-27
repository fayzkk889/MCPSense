package detection

import (
	"crypto/sha256"
	"embed"
	"fmt"
	"strings"
)

// Source identity is an equivalence guard, not a signature or proof that a
// report is authentic. Keep this list in sync with production detection files.
//
//go:embed patterns.go injection.go mcp_vectors.go directives.go profile.go intent.go boundaries.go
var detectorSources embed.FS

var sourceProfile = SourceDigest(detectorSources)

func Profile() string { return sourceProfile }

// SourceDigest hashes sorted embedded file names and normalized source bytes,
// so Windows checkout line endings do not change a detector's identity.
func SourceDigest(sources embed.FS) string {
	hash := sha256.New()
	entries, err := sources.ReadDir(".")
	if err != nil {
		panic(err)
	}
	for _, entry := range entries {
		data, err := sources.ReadFile(entry.Name())
		if err != nil {
			panic(err)
		}
		_, _ = fmt.Fprintf(hash, "%s\x00%s\x00", entry.Name(), strings.ReplaceAll(string(data), "\r\n", "\n"))
	}
	return fmt.Sprintf("%x", hash.Sum(nil))
}
