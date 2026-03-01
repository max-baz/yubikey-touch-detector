package notifier

import (
	"os/exec"
	"sync"

	"github.com/godbus/dbus/v5"
	log "github.com/sirupsen/logrus"
)

const (
	plymouthDest  = "org.freedesktop.Plymouth"
	plymouthPath  = "/org/freedesktop/Plymouth"
	plymouthIface = "org.freedesktop.Plymouth"
)

func SetupPlymouthNotifier(notifiers *sync.Map, fallbackExec bool) {
	touch := make(chan Message, 10)
	notifiers.Store("notifier/plymouth", touch)

	message := "YubiKey is waiting for a touch..."
	activeTouchWaits := 0

	// Initialize System Bus connection
	conn, err := dbus.SystemBus()
	if err != nil {
		log.Warn("Could not connect to System Bus: ", err)
		if !fallbackExec {
			log.Error("D-Bus failed and fallbackExec is disabled. Plymouth notifier will be inactive.")
			return
		}
	} else {
		defer conn.Close()
	}

	for value := range touch {
		if value == GPG_ON || value == U2F_ON || value == HMAC_ON {
			activeTouchWaits++
		}
		if value == GPG_OFF || value == U2F_OFF || value == HMAC_OFF {
			activeTouchWaits--
			if activeTouchWaits < 0 {
				activeTouchWaits = 0
			}
		}

		if activeTouchWaits > 0 {
			showPlymouthMessage(conn, message, fallbackExec)
		} else {
			hidePlymouthMessage(conn, message, fallbackExec)
		}
	}
}

func showPlymouthMessage(conn *dbus.Conn, msg string, fallbackExec bool) {
	// 1. Try D-Bus if connection exists
	if conn != nil {
		obj := conn.Object(plymouthDest, dbus.ObjectPath(plymouthPath))
		call := obj.Call(plymouthIface+".DisplayMessage", 0, msg)
		if call.Err == nil {
			return
		}
		log.Warn("Plymouth D-Bus DisplayMessage failed: ", call.Err)
	}

	// 2. Try CLI Fallback if enabled
	if fallbackExec {
		cmd := exec.Command("plymouth", "display-message", "--text", msg)
		if err := cmd.Run(); err != nil {
			log.Error("Plymouth CLI fallback failed: ", err)
		}
	}
}

func hidePlymouthMessage(conn *dbus.Conn, msg string, fallbackExec bool) {
	// 1. Try D-Bus if connection exists
	if conn != nil {
		obj := conn.Object(plymouthDest, dbus.ObjectPath(plymouthPath))
		call := obj.Call(plymouthIface+".HideMessage", 0, msg)
		if call.Err == nil {
			return
		}
		log.Warn("Plymouth D-Bus HideMessage failed: ", call.Err)
	}

	// 2. Try CLI Fallback if enabled
	if fallbackExec {
		cmd := exec.Command("plymouth", "hide-message", "--text", msg)
		if err := cmd.Run(); err != nil {
			log.Error("Plymouth CLI hide fallback failed: ", err)
		}
	}
}

// Post-Boot-Stage

// ❯ ./result/bin/yubikey-touch-detector --no-socket --plymouth

// WARN[2026-03-01T00:18:21+01:00] Plymouth DisplayMessage failed (is Plymouth running?): The name org.freedesktop.Plymouth was not provided by any .service files
// WARN[2026-03-01T00:18:28+01:00] Plymouth HideMessage failed: The name org.freedesktop.Plymouth was not provided by any .service files
