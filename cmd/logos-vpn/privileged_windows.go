package main

import "golang.org/x/sys/windows"

// privileged: an adapter and routes are an administrator's to add.
func privileged() error {
	if !windows.GetCurrentProcessToken().IsElevated() {
		return errElevated
	}
	return nil
}

type elevatedError struct{}

func (elevatedError) Error() string {
	return "an adapter and routes are an administrator's to add: run it in an elevated PowerShell"
}

var errElevated error = elevatedError{}
