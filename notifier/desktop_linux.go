package notifier

import "sync"

func SetupDesktopNotifier(notifiers *sync.Map, title, body, urgency string) {
	setupLibnotifyNotifier(notifiers, title, body, urgency)
}
