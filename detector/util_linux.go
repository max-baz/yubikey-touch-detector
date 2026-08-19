package detector

import (
	"github.com/rjeczalik/notify"
	log "github.com/sirupsen/logrus"
)

func initInotifyWatcher(detector string, path string, eventTypes ...notify.Event) chan notify.EventInfo {
	events := make(chan notify.EventInfo, 10)
	if err := notify.Watch(path, events, eventTypes...); err != nil {
		log.Errorf("Cannot establish a %v watch on '%v': %v", detector, path, err)
		return events
	}
	log.Debugf("%v watcher on '%v' is successfully established", detector, path)
	return events
}
