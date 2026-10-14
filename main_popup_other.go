//go:build !linux

package main

import "fmt"

// showPopup reports that the built-in touch dialog is Linux only
func showPopup(args []string) {
	fmt.Println("The built-in touch dialog is only supported on Linux")
}
