//go:build linux

package main

import (
	"os"

	"github.com/maximbaz/yubikey-touch-detector/notifier"
	"github.com/maximbaz/yubikey-touch-detector/popup"
)

// showPopup runs the built-in touch dialog (Linux only; the GUI toolkit
// requires a Linux build with cgo). The detector passes its content through
// the environment; arguments are accepted for trying the dialog by hand,
// e.g. "yubikey-touch-detector popup u2f 'SSH to host'".
func showPopup(args []string) {
	options := popup.Options{
		Reasons:  os.Getenv(notifier.PopupReasonsEnv),
		Details:  os.Getenv(notifier.PopupDetailsEnv),
		Position: os.Getenv(notifier.PopupPositionEnv),
	}
	if len(args) > 0 {
		options.Reasons = args[0]
	}
	if len(args) > 1 {
		options.Details = args[1]
	}
	if options.Position == "" {
		options.Position = notifier.DefaultPopupPosition
	}
	popup.Run(options)
}
