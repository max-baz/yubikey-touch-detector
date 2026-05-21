package notifier

import (
	"fmt"
	"sync"
)

// SetupStdoutNotifier configures a notifier to log to stdout
func SetupStdoutNotifier(notifiers *sync.Map) {
	touch := make(chan TouchEvent, 10)
	notifiers.Store("notifier/stdout", touch)

	for {
		event := <-touch
		fmt.Println(event.Type)
	}
}
