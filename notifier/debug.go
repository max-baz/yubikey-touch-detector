package notifier

import (
	"sync"

	log "github.com/sirupsen/logrus"
)

// SetupDebugNotifier configures a notifier to log all touch events
func SetupDebugNotifier(notifiers *sync.Map) {
	touch := make(chan TouchEvent, 10)
	notifiers.Store("notifier/debug", touch)

	for {
		event := <-touch
		if event.Context != "" {
			log.Debug("[notifiers/debug] ", event.Type, " (", event.Context, ")")
		} else {
			log.Debug("[notifiers/debug] ", event.Type)
		}
	}
}
