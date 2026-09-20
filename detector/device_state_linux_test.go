package detector

import (
	"testing"

	"github.com/maximbaz/yubikey-touch-detector/notifier"
)

func TestHMACDeviceStateDistinguishesUnplugFromWaiting(t *testing.T) {
	state := newHMACDeviceState()
	state.add("/dev/hidraw0", "key-a")
	state.add("/dev/hidraw1", "key-a")
	state.add("/dev/hidraw2", "key-b")
	state.add("/dev/hidraw3", "key-b")

	state.remove("/dev/hidraw0")
	if message, changed := state.message(); !changed || message != notifier.HMAC_ON {
		t.Fatalf("partial removal = %q, %t, want %q, true", message, changed, notifier.HMAC_ON)
	}

	state.add("/dev/hidraw4", "key-a")
	if message, changed := state.message(); !changed || message != notifier.HMAC_OFF {
		t.Fatalf("interface return = %q, %t, want %q, true", message, changed, notifier.HMAC_OFF)
	}

	state.remove("/dev/hidraw2")
	state.remove("/dev/hidraw3")
	if message, changed := state.message(); changed {
		t.Fatalf("full key removal = %q, true, want no change", message)
	}
}

func TestHMACDeviceStateClearsWaitWhenKeyIsUnplugged(t *testing.T) {
	state := newHMACDeviceState()
	state.add("/dev/hidraw0", "key-a")
	state.add("/dev/hidraw1", "key-a")
	state.remove("/dev/hidraw0")
	state.message()

	state.remove("/dev/hidraw1")
	if message, changed := state.message(); !changed || message != notifier.HMAC_OFF {
		t.Fatalf("remaining interface removal = %q, %t, want %q, true", message, changed, notifier.HMAC_OFF)
	}
}

func TestHMACDeviceStateKeepsOtherPendingKeysActive(t *testing.T) {
	state := newHMACDeviceState()
	state.add("/dev/hidraw0", "key-a")
	state.add("/dev/hidraw1", "key-a")
	state.add("/dev/hidraw2", "key-b")
	state.add("/dev/hidraw3", "key-b")
	state.remove("/dev/hidraw0")
	state.remove("/dev/hidraw2")
	state.message()

	state.add("/dev/hidraw4", "key-a")
	if message, changed := state.message(); changed {
		t.Fatalf("one interface return = %q, true, want no change", message)
	}

	state.add("/dev/hidraw5", "key-b")
	if message, changed := state.message(); !changed || message != notifier.HMAC_OFF {
		t.Fatalf("all interfaces return = %q, %t, want %q, true", message, changed, notifier.HMAC_OFF)
	}
}

func TestU2FTouchStateAggregatesWatchers(t *testing.T) {
	state := newU2FTouchState()
	if message, changed := state.update(1, true); !changed || message != notifier.U2F_ON {
		t.Fatalf("first watcher on = %q, %t, want %q, true", message, changed, notifier.U2F_ON)
	}
	if message, changed := state.update(2, true); changed {
		t.Fatalf("second watcher on = %q, true, want no change", message)
	}
	if message, changed := state.update(1, false); changed {
		t.Fatalf("first watcher off = %q, true, want no change", message)
	}
	if message, changed := state.update(2, false); !changed || message != notifier.U2F_OFF {
		t.Fatalf("last watcher off = %q, %t, want %q, true", message, changed, notifier.U2F_OFF)
	}
}
