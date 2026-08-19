package notifier

import (
	"fmt"
	"os/exec"
	"strings"
	"sync"

	log "github.com/sirupsen/logrus"
)

func SetupDesktopNotifier(notifiers *sync.Map, title, body string) {
	touch := make(chan Message, 10)
	notifiers.Store("notifier/desktop", touch)

	activeTouchWaits := 0
	for value := range touch {
		wasActive := activeTouchWaits > 0
		switch value {
		case GPG_ON, U2F_ON, HMAC_ON:
			activeTouchWaits++
		case GPG_OFF, U2F_OFF, HMAC_OFF:
			if activeTouchWaits > 0 {
				activeTouchWaits--
			}
		}
		if !wasActive && activeTouchWaits > 0 {
			if err := showMacOSNotification(title, body); err != nil {
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
