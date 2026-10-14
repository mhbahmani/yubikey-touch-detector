//go:build linux

package main

import "github.com/maximbaz/yubikey-touch-detector/popup"

// showPopup runs the built-in touch dialog (Linux only; the GUI toolkit
// requires a Linux build with cgo)
func showPopup(args []string) {
	var reason, details string
	if len(args) > 0 {
		reason = args[0]
	}
	if len(args) > 1 {
		details = args[1]
	}
	popup.Run(reason, details)
}
