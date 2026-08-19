package detector

import (
	"fmt"
	"os"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/deckarep/golang-set"
	"github.com/rjeczalik/notify"
	log "github.com/sirupsen/logrus"

	"github.com/maximbaz/yubikey-touch-detector/notifier"
)

// WatchHMAC watches when YubiKey is waiting for a touch on a HMAC request
func WatchHMAC(notifiers *sync.Map) {
	devicesEvents := initInotifyWatcher("HMAC", "/dev", notify.Create, notify.Remove)
	defer notify.Stop(devicesEvents)

	yubikeyHidrawDevices := mapset.NewSet()
	if devices, err := os.ReadDir("/dev"); err == nil {
		for _, device := range devices {
			devicePath := path.Join("/dev", device.Name())
			if isYubikeyHidrawDevice(devicePath) {
				yubikeyHidrawDevices.Add(devicePath)
			}
		}
	} else {
		log.Errorf("Cannot list devices in '/dev' to find connected YubiKeys: %v", err)
	}

	lastMessage := notifier.HMAC_OFF
	var onRemoveTimer *time.Timer
	for event := range devicesEvents {
		switch event.Event() {
		case notify.Create:
			if onRemoveTimer != nil {
				onRemoveTimer.Stop()
			}
			// Give a second for device to initialize
			time.Sleep(1 * time.Second)

			if isYubikeyHidrawDevice(event.Path()) {
				yubikeyHidrawDevices.Add(event.Path())

				newMessage := notifier.HMAC_OFF
				if lastMessage != newMessage {
					notifiers.Range(func(_, v interface{}) bool {
						v.(chan notifier.Message) <- newMessage
						return true
					})
				}
				lastMessage = newMessage
			}
		case notify.Remove:
			if yubikeyHidrawDevices.Contains(event.Path()) {
				if onRemoveTimer != nil {
					onRemoveTimer.Stop()
				}

				yubikeyHidrawDevices.Remove(event.Path())

				onRemoveTimer = time.AfterFunc(1*time.Second, func() {
					newMessage := notifier.HMAC_OFF
					if yubikeyHidrawDevices.Cardinality() > 0 {
						newMessage = notifier.HMAC_ON
					}

					if lastMessage != newMessage {
						notifiers.Range(func(_, v interface{}) bool {
							v.(chan notifier.Message) <- newMessage
							return true
						})
					}

					lastMessage = newMessage
				})
			}
		}
	}
}

func isYubikeyHidrawDevice(devicePath string) bool {
	if strings.HasPrefix(devicePath, "/dev/hidraw") {
		if info, err := os.ReadFile(fmt.Sprintf("/sys/class/hidraw/%v/device/uevent", path.Base(devicePath))); err == nil {
			if strings.Contains(strings.ToLower(string(info)), "yubikey") {
				return true
			}
		}
	}
	return false
}
