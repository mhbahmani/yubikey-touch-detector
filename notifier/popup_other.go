//go:build !linux

package notifier

import (
	"sync"

	log "github.com/sirupsen/logrus"
)

// SetupPopupNotifier is only implemented on Linux, where the built-in
// touch dialog is available
func SetupPopupNotifier(notifiers *sync.Map, position string) {
	log.Error("The built-in touch dialog is only supported on Linux")
}
