package detector

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/rjeczalik/notify"
	log "github.com/sirupsen/logrus"

	"github.com/maximbaz/yubikey-touch-detector/notifier"
)

type hmacDeviceState struct {
	deviceByPath  map[string]string
	pathsByDevice map[string]map[string]bool
	pending       map[string]bool
	active        bool
}

func newHMACDeviceState() *hmacDeviceState {
	return &hmacDeviceState{
		deviceByPath:  make(map[string]string),
		pathsByDevice: make(map[string]map[string]bool),
		pending:       make(map[string]bool),
	}
}

func (state *hmacDeviceState) add(devicePath, deviceID string) {
	if previousID, exists := state.deviceByPath[devicePath]; exists && previousID != deviceID {
		delete(state.pathsByDevice[previousID], devicePath)
		if len(state.pathsByDevice[previousID]) == 0 {
			delete(state.pathsByDevice, previousID)
			delete(state.pending, previousID)
		}
	}
	state.deviceByPath[devicePath] = deviceID
	if state.pathsByDevice[deviceID] == nil {
		state.pathsByDevice[deviceID] = make(map[string]bool)
	}
	state.pathsByDevice[deviceID][devicePath] = true
	delete(state.pending, deviceID)
}

func (state *hmacDeviceState) remove(devicePath string) bool {
	deviceID, exists := state.deviceByPath[devicePath]
	if !exists {
		return false
	}
	delete(state.deviceByPath, devicePath)
	delete(state.pathsByDevice[deviceID], devicePath)
	if len(state.pathsByDevice[deviceID]) == 0 {
		delete(state.pathsByDevice, deviceID)
		delete(state.pending, deviceID)
	} else {
		state.pending[deviceID] = true
	}
	return true
}

func (state *hmacDeviceState) message() (notifier.Message, bool) {
	active := len(state.pending) > 0
	if active == state.active {
		return "", false
	}
	state.active = active
	if active {
		return notifier.HMAC_ON, true
	}
	return notifier.HMAC_OFF, true
}

// WatchHMAC watches when YubiKey is waiting for a touch on a HMAC request
func WatchHMAC(notifiers *sync.Map) {
	devicesEvents := initInotifyWatcher("HMAC", "/dev", notify.Create, notify.Remove)
	defer notify.Stop(devicesEvents)

	state := newHMACDeviceState()
	if devices, err := os.ReadDir("/dev"); err == nil {
		for _, device := range devices {
			devicePath := filepath.Join("/dev", device.Name())
			if deviceID, found := yubikeyDeviceID(devicePath); found {
				state.add(devicePath, deviceID)
			}
		}
	} else {
		log.Errorf("Cannot list devices in '/dev' to find connected YubiKeys: %v", err)
	}

	readyDevices := make(chan string, 10)
	var debounceTimer *time.Timer
	var debounce <-chan time.Time
	publish := func() {
		if message, changed := state.message(); changed {
			notifiers.Range(func(_, value interface{}) bool {
				value.(chan notifier.Message) <- message
				return true
			})
		}
	}
	resetDebounce := func() {
		if debounceTimer == nil {
			debounceTimer = time.NewTimer(time.Second)
		} else {
			if !debounceTimer.Stop() {
				select {
				case <-debounceTimer.C:
				default:
				}
			}
			debounceTimer.Reset(time.Second)
		}
		debounce = debounceTimer.C
	}

	for {
		select {
		case event, ok := <-devicesEvents:
			if !ok {
				return
			}
			switch event.Event() {
			case notify.Create:
				devicePath := event.Path()
				go func() {
					time.Sleep(time.Second)
					readyDevices <- devicePath
				}()
			case notify.Remove:
				if state.remove(event.Path()) {
					resetDebounce()
				}
			}
		case devicePath := <-readyDevices:
			if deviceID, found := yubikeyDeviceID(devicePath); found {
				state.add(devicePath, deviceID)
				publish()
			}
		case <-debounce:
			debounce = nil
			publish()
		}
	}
}

func yubikeyDeviceID(devicePath string) (string, bool) {
	if !strings.HasPrefix(devicePath, "/dev/hidraw") {
		return "", false
	}

	sysfsPath, err := filepath.EvalSymlinks(filepath.Join("/sys/class/hidraw", filepath.Base(devicePath), "device"))
	if err != nil {
		return "", false
	}
	for current := sysfsPath; current != filepath.Dir(current); current = filepath.Dir(current) {
		vendor, err := os.ReadFile(filepath.Join(current, "idVendor"))
		if err == nil && strings.EqualFold(strings.TrimSpace(string(vendor)), "1050") {
			return current, true
		}
	}
	return "", false
}
