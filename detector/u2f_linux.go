package detector

import (
	"os"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/rjeczalik/notify"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"

	"github.com/maximbaz/yubikey-touch-detector/notifier"
)

const (
	// https://fidoalliance.org/specs/u2f-specs-master/inc/u2f_hid.h
	// and its backwards-compatible successor
	// https://fidoalliance.org/specs/fido2/fido-client-to-authenticator-protocol-v2.1-rd-20191217.html
	TYPE_INIT          = 0x80
	CTAPHID_MSG        = TYPE_INIT | 0x03
	CTAPHID_KEEPALIVE  = TYPE_INIT | 0x3b
	FIDO_USAGE_PAGE    = 0xf1d0
	FIDO_USAGE_CTAPHID = 0x01
	STATUS_UPNEEDED    = 0x02

	// https://fidoalliance.org/specs/u2f-specs-master/inc/u2f.h
	U2F_SW_CONDITIONS_NOT_SATISFIED = 0x6985

	// https://github.com/torvalds/linux/blob/master/include/linux/hid.h
	HID_ITEM_TYPE_GLOBAL           = 1
	HID_ITEM_TYPE_LOCAL            = 2
	HID_GLOBAL_ITEM_TAG_USAGE_PAGE = 0
	HID_LOCAL_ITEM_TAG_USAGE       = 0
)

type u2fWatcherEvent struct {
	id         uint64
	devicePath string
	active     bool
	done       bool
}

type u2fTouchState struct {
	active map[uint64]bool
}

func newU2FTouchState() *u2fTouchState {
	return &u2fTouchState{active: make(map[uint64]bool)}
}

func (state *u2fTouchState) update(id uint64, active bool) (notifier.Message, bool) {
	wasActive := len(state.active) > 0
	if active {
		state.active[id] = true
	} else {
		delete(state.active, id)
	}
	isActive := len(state.active) > 0
	if wasActive == isActive {
		return "", false
	}
	if isActive {
		return notifier.U2F_ON, true
	}
	return notifier.U2F_OFF, true
}

// WatchU2F watches when YubiKey is waiting for a touch on a U2F request
func WatchU2F(notifiers *sync.Map) {
	devicesEvents := initInotifyWatcher("U2F", "/dev", notify.Create)
	defer notify.Stop(devicesEvents)

	watcherEvents := make(chan u2fWatcherEvent, 32)
	readyDevices := make(chan string, 10)
	watchers := make(map[string]uint64)
	pendingWatchers := make(map[string]bool)
	state := newU2FTouchState()
	var nextWatcherID uint64

	publish := func(message notifier.Message) {
		notifiers.Range(func(_, value interface{}) bool {
			value.(chan notifier.Message) <- message
			return true
		})
	}
	startWatcher := func(devicePath string) {
		if _, exists := watchers[devicePath]; exists {
			pendingWatchers[devicePath] = true
			return
		}
		delete(pendingWatchers, devicePath)
		if !isFidoU2FDevice(devicePath) {
			return
		}
		nextWatcherID++
		watchers[devicePath] = nextWatcherID
		go runU2FWatcher(devicePath, nextWatcherID, watcherEvents)
	}

	if devices, err := os.ReadDir("/dev"); err == nil {
		for _, device := range devices {
			startWatcher(path.Join("/dev", device.Name()))
		}
	} else {
		log.Errorf("Cannot list devices in '/dev' to find connected YubiKeys: %v", err)
	}

	for {
		select {
		case event, ok := <-devicesEvents:
			if !ok {
				return
			}
			devicePath := event.Path()
			go func() {
				time.Sleep(time.Second)
				readyDevices <- devicePath
			}()
		case devicePath := <-readyDevices:
			startWatcher(devicePath)
		case event := <-watcherEvents:
			if message, changed := state.update(event.id, event.active); changed {
				publish(message)
			}
			if event.done && watchers[event.devicePath] == event.id {
				delete(watchers, event.devicePath)
				if pendingWatchers[event.devicePath] {
					startWatcher(event.devicePath)
				}
			}
		}
	}
}

func isFidoU2FDevice(devicePath string) bool {
	if !strings.HasPrefix(devicePath, "/dev/hidraw") {
		return false
	}

	device, err := os.Open(devicePath)
	if err != nil {
		return false
	}
	defer device.Close()

	size, err := unix.IoctlGetUint32(int(device.Fd()), unix.HIDIOCGRDESCSIZE)
	if err != nil {
		log.Warnf("Cannot get descriptor size for device '%v': %v", devicePath, err)
		return false
	}

	data := unix.HIDRawReportDescriptor{Size: size}
	if err := unix.IoctlHIDGetDesc(int(device.Fd()), &data); err != nil {
		log.Warnf("Cannot get descriptor for device '%v': %v", devicePath, err)
		return false
	}

	isFido := false
	hasU2F := false
	for i := uint32(0); i < size; {
		prefix := data.Value[i]
		tag := (prefix & 0b11110000) >> 4
		typ := (prefix & 0b00001100) >> 2
		size := prefix & 0b00000011

		val1b := data.Value[i+1]
		val2b := int(data.Value[i+1]) | (int(data.Value[i+2]) << 8)

		if typ == HID_ITEM_TYPE_GLOBAL && tag == HID_GLOBAL_ITEM_TAG_USAGE_PAGE && val2b == FIDO_USAGE_PAGE {
			isFido = true
		} else if typ == HID_ITEM_TYPE_LOCAL && tag == HID_LOCAL_ITEM_TAG_USAGE && val1b == FIDO_USAGE_CTAPHID {
			hasU2F = true
		}

		if isFido && hasU2F {
			return true
		}

		i += uint32(size) + 1
	}

	return false
}

func runU2FWatcher(devicePath string, id uint64, events chan<- u2fWatcherEvent) {
	device, err := os.Open(devicePath)
	if err != nil {
		log.Errorf("Cannot open device '%v' to run U2F watcher: %v", devicePath, err)
		events <- u2fWatcherEvent{id: id, devicePath: devicePath, done: true}
		return
	}
	defer device.Close()

	payload := make([]byte, 64)
	var mutex sync.Mutex
	var active bool
	var offTimer *time.Timer
	var generation uint64

	stop := func() {
		mutex.Lock()
		generation++
		if offTimer != nil {
			offTimer.Stop()
			offTimer = nil
		}
		active = false
		events <- u2fWatcherEvent{id: id, devicePath: devicePath, done: true}
		mutex.Unlock()
	}

	for {
		n, err := device.Read(payload)
		if err != nil {
			stop()
			return
		}
		if n < 9 {
			continue
		}

		val1b := payload[7]
		val2b := (int(payload[7]) << 8) | int(payload[8])
		waiting := payload[4] == CTAPHID_MSG && val2b == U2F_SW_CONDITIONS_NOT_SATISFIED ||
			payload[4] == CTAPHID_KEEPALIVE && val1b == STATUS_UPNEEDED

		mutex.Lock()
		generation++
		currentGeneration := generation
		if offTimer != nil {
			offTimer.Stop()
			offTimer = nil
		}
		emitOn := waiting && !active
		if waiting {
			active = true
		}
		if active {
			duration := 200 * time.Millisecond
			if waiting {
				duration = 2 * time.Second
			}
			offTimer = time.AfterFunc(duration, func() {
				mutex.Lock()
				if generation != currentGeneration || !active {
					mutex.Unlock()
					return
				}
				active = false
				offTimer = nil
				events <- u2fWatcherEvent{id: id, devicePath: devicePath}
				mutex.Unlock()
			})
		}
		if emitOn {
			events <- u2fWatcherEvent{id: id, devicePath: devicePath, active: true}
		}
		mutex.Unlock()
	}
}
