//go:build !linux

package detector

import "net"

// sshRequestDetail is only implemented on Linux, where the ssh client can be
// identified through /proc
func sshRequestDetail(_ net.Conn) string {
	return ""
}
