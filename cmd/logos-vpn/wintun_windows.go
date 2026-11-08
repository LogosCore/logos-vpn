//go:build wintun

package main

import (
	"bytes"
	_ "embed"
	"os"
	"path/filepath"
)

// wintunDLL is Wintun's signed driver library for this build's
// architecture (wintun.net, unmodified, as its license lets it go with an
// application): the Makefile puts it here before a Windows build.
//
//go:embed wintun/wintun.dll
var wintunDLL []byte

// ensureWintun writes Wintun's library beside the executable, where
// wireguard-go's tun loads it from, unless the same is there.
func ensureWintun() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	path := filepath.Join(filepath.Dir(exe), "wintun.dll")
	if have, err := os.ReadFile(path); err == nil && bytes.Equal(have, wintunDLL) {
		return nil
	}
	return os.WriteFile(path, wintunDLL, 0o644)
}
