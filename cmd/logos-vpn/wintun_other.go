//go:build !wintun

package main

// ensureWintun: a build without Wintun inside (a non-Windows one, or a
// Windows one built without the wintun tag) finds wintun.dll beside the
// executable, or in System32, as it is.
func ensureWintun() error { return nil }
