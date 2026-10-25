//go:build !js

package scanner

import "net/http"

func liveRuntimeTransport(bool) http.RoundTripper { return nil }
