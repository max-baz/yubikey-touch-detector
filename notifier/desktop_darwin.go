package notifier

import (
	"fmt"
	"os/exec"
	"strings"
	"sync"

	log "github.com/sirupsen/logrus"
)

func SetupDesktopNotifier(notifiers *sync.Map, title, body string) {
	templates, err := newNotificationTemplates(title, body)
	if err != nil {
		log.Error("Cannot initialize desktop notifications: ", err)
		return
	}

	touch := make(chan Message, 10)
	notifiers.Store("notifier/desktop", touch)

	state := newTouchState()
	for value := range touch {
		wasActive, isActive, _ := state.update(value)
		if !wasActive && isActive {
			renderedTitle, renderedBody, err := templates.render(state.reasons())
			if err != nil {
				log.Error("Cannot render desktop notification: ", err)
				continue
			}
			if err := showMacOSNotification(renderedTitle, renderedBody); err != nil {
				log.Error("Cannot show desktop notification: ", err)
			}
		}
	}
}

func showMacOSNotification(title, body string) error {
	output, err := exec.Command(
		"/usr/bin/osascript",
		"-e",
		`on run argv
set notificationTitle to item 1 of argv
set notificationBody to item 2 of argv
if notificationTitle is "" then
	display notification notificationBody
else
	display notification notificationBody with title notificationTitle
end if
end run`,
		"--",
		title,
		body,
	).CombinedOutput()
	if err != nil && len(output) > 0 {
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(output)))
	}
	return err
}
