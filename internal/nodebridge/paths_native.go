//go:build !js

package nodebridge

import (
	"os"
	"path/filepath"
	"runtime"
)

func Abs(p string) (string, error)              { return filepath.Abs(p) }
func Dir(p string) string                       { return filepath.Dir(p) }
func Base(p string) string                      { return filepath.Base(p) }
func MkdirAll(p string, mode os.FileMode) error { return os.MkdirAll(p, mode) }
func RuntimeID() string                         { return runtime.GOOS + "/" + runtime.GOARCH }
