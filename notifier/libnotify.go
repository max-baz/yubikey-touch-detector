package notifier

import (
	"sync"
	"sync/atomic"

	"github.com/esiqveland/notify"
	"github.com/godbus/dbus/v5"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

// SetupLibnotifyNotifier configures a notifier to show all touch requests with libnotify
func SetupLibnotifyNotifier(notifiers *sync.Map) {
	touch := make(chan Message, 10)
	notifiers.Store("notifier/libnotify", touch)

	notification := notify.Notification{
		AppName: "yubikey-touch-detector",
		AppIcon: "yubikey-touch-detector",
		Summary: "YubiKey is waiting for a touch",
	}
	notification.AddHint(notify.Hint{ID: "transient", Variant: dbus.MakeVariant(true)})

	conn, notifier, err := connectDBus(&notification.ReplacesID)
	if err != nil {
		log.Error("Cannot initialize desktop notifications: ", err)
		return
	}
	defer conn.Close()
	defer notifier.Close()

	activeTouchWaits := 0

	for {
		value := <-touch
		if value == GPG_ON || value == U2F_ON || value == HMAC_ON {
			activeTouchWaits++
		}
		if value == GPG_OFF || value == U2F_OFF || value == HMAC_OFF {
			activeTouchWaits--
		}
		if activeTouchWaits > 0 {
			id, err := notifier.SendNotification(notification)
			if err != nil {
				log.Error("Cannot show notification (will reconnect to DBUS): ", err)
				notifier.Close()
				conn.Close()
				conn, notifier, err = connectDBus(&notification.ReplacesID)
				if err != nil {
					log.Error("Failed to reconnect: ", err)
					continue
				}
				id, err = notifier.SendNotification(notification)
				if err != nil {
					log.Error("Cannot show notification after reconnect: ", err)
					continue
				}
			}
			atomic.CompareAndSwapUint32(&notification.ReplacesID, 0, id)
		} else if id := atomic.LoadUint32(&notification.ReplacesID); id != 0 {
			if _, err := notifier.CloseNotification(id); err != nil {
				log.Error("Cannot close notification (will reconnect to DBUS): ", err)
				notifier.Close()
				conn.Close()
				conn, notifier, err = connectDBus(&notification.ReplacesID)
				if err != nil {
					log.Error("Failed to reconnect: ", err)
				}
			}
		}
	}
}

func connectDBus(replacesID *uint32) (*dbus.Conn, notify.Notifier, error) {
	conn, err := dbus.SessionBusPrivate()
	if err != nil {
		return nil, nil, errors.Wrapf(err, "unable to create session bus")
	}

	if err := conn.Auth(nil); err != nil {
		conn.Close()
		return nil, nil, errors.Wrapf(err, "unable to authenticate")
	}

	if err := conn.Hello(); err != nil {
		conn.Close()
		return nil, nil, errors.Wrapf(err, "unable get bus name")
	}

	reset := func(msg *notify.NotificationClosedSignal) {
		atomic.CompareAndSwapUint32(replacesID, msg.ID, 0)
	}

	notifier, err := notify.New(
		conn,
		notify.WithOnClosed(reset),
		notify.WithLogger(log.StandardLogger()),
	)
	if err != nil {
		conn.Close()
		return nil, nil, errors.Wrapf(err, "unable to initialize D-Bus notifier interface")
	}

	return conn, notifier, nil
}
