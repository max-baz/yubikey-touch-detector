package notifier

import "sync"

func SetupDesktopNotifier(notifiers *sync.Map, title, body string) {
	setupLibnotifyNotifier(notifiers, title, body)
}
