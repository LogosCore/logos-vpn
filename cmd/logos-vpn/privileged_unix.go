//go:build !windows

package main

import (
	"errors"
	"os"
)

// privileged: an interface and routes are the system's, root's to add.
func privileged() error {
	if os.Geteuid() != 0 {
		return errors.New("an interface and routes are root's to add: sudo logos-vpn …")
	}
	return nil
}
