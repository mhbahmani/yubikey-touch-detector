//go:build !linux

package detector

import (
	"net"

	"github.com/maximbaz/yubikey-touch-detector/notifier"
)

// sshRequestDetail is only implemented on Linux, where the ssh client can be
// identified through /proc
func sshRequestDetail(_ net.Conn) notifier.TouchContext {
	return notifier.TouchContext{}
}
