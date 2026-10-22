package report

import "testing"

func TestArtifactURI(t *testing.T) {
	for path, want := range map[string]string{"src/server.go": "src/server.go", "src/my server.go": "src/my%20server.go", `C:\work\my server.go`: "file:///C:/work/my%20server.go", "/tmp/server.go": "file:///tmp/server.go"} {
		if got := artifactURI(path); got != want {
			t.Errorf("%q => %q want %q", path, got, want)
		}
	}
}
