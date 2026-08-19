package notifier

import (
	"sync"

	"github.com/esiqveland/notify"
	"github.com/godbus/dbus/v5"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

const notificationsInterface = "org.freedesktop.Notifications"
const notificationsClosedSignal = notificationsInterface + ".NotificationClosed"
const notificationsPath dbus.ObjectPath = "/org/freedesktop/Notifications"
const nameHasNoOwnerError = "org.freedesktop.DBus.Error.NameHasNoOwner"

type notificationReference struct {
	owner string
	id    uint32
}

func (reference *notificationReference) useOwner(owner string) {
	if reference.owner != owner {
		reference.owner = owner
		reference.id = 0
	}
}

func (reference *notificationReference) handleSignal(signal *dbus.Signal) {
	if signal == nil || signal.Name != notificationsClosedSignal || reference.owner != signal.Sender || len(signal.Body) == 0 {
		return
	}
	id, ok := signal.Body[0].(uint32)
	if ok && reference.id == id {
		reference.id = 0
	}
}

// SetupLibnotifyNotifier configures a notifier to show all touch requests with libnotify
func SetupLibnotifyNotifier(notifiers *sync.Map) {
	setupLibnotifyNotifier(notifiers, DefaultNotificationTitle, DefaultNotificationBody)
}

func setupLibnotifyNotifier(notifiers *sync.Map, title, body string) {
	touch := make(chan Message, 10)
	notifiers.Store("notifier/libnotify", touch)

	notification := notify.Notification{
		AppName: "yubikey-touch-detector",
		AppIcon: "yubikey-touch-detector",
		Summary: title,
		Body:    body,
	}
	notification.AddHint(notify.Hint{ID: "transient", Variant: dbus.MakeVariant(true)})

	conn, signals, err := connectDBus()
	if err != nil {
		log.Error("Cannot initialize desktop notifications: ", err)
		return
	}
	defer func() {
		conn.Close()
	}()

	activeTouchWaits := 0
	reference := notificationReference{}

	for {
		var value Message
		select {
		case signal, ok := <-signals:
			if ok {
				reference.handleSignal(signal)
			} else {
				signals = nil
			}
			continue
		case value = <-touch:
		}
		if value == GPG_ON || value == U2F_ON || value == HMAC_ON {
			activeTouchWaits++
		}
		if value == GPG_OFF || value == U2F_OFF || value == HMAC_OFF {
			activeTouchWaits--
		}
		if activeTouchWaits > 0 {
			if err := showNotification(conn, &reference, &notification); err != nil {
				log.Error("Cannot show notification (will reconnect to DBUS): ", err)
				newConn, newSignals, err := reconnectDBus(conn, &reference)
				if err != nil {
					log.Error("Failed to reconnect: ", err)
					continue
				}
				conn, signals = newConn, newSignals
				if err = showNotification(conn, &reference, &notification); err != nil {
					log.Error("Cannot show notification after reconnect: ", err)
				}
			}
		} else if reference.id != 0 {
			if err := closeTrackedNotification(conn, &reference); err != nil {
				log.Error("Cannot close notification (will reconnect to DBUS): ", err)
				newConn, newSignals, err := reconnectDBus(conn, &reference)
				if err != nil {
					log.Error("Failed to reconnect: ", err)
					continue
				}
				conn, signals = newConn, newSignals
			}
		}
	}
}

func showNotification(conn *dbus.Conn, reference *notificationReference, notification *notify.Notification) error {
	owner, err := notificationOwner(conn)
	if err != nil {
		return err
	}
	reference.useOwner(owner)
	notification.ReplacesID = reference.id
	id, err := sendNotification(conn, owner, *notification)
	if err != nil {
		return err
	}
	reference.id = id
	return nil
}

func closeTrackedNotification(conn *dbus.Conn, reference *notificationReference) error {
	owner, err := notificationOwner(conn)
	if err != nil {
		return err
	}
	reference.useOwner(owner)
	if reference.id == 0 {
		return nil
	}
	if err := closeNotification(conn, owner, reference.id); err != nil {
		return err
	}
	reference.id = 0
	return nil
}

func notificationOwner(conn *dbus.Conn) (string, error) {
	var owner string
	err := conn.BusObject().Call("org.freedesktop.DBus.GetNameOwner", 0, notificationsInterface).Store(&owner)
	if err == nil {
		return owner, nil
	}
	if !isNameHasNoOwnerError(err) {
		return "", errors.Wrap(err, "unable to get notification server owner")
	}
	if err := conn.BusObject().Call("org.freedesktop.DBus.StartServiceByName", 0, notificationsInterface, uint32(0)).Err; err != nil {
		return "", errors.Wrap(err, "unable to start notification server")
	}
	if err := conn.BusObject().Call("org.freedesktop.DBus.GetNameOwner", 0, notificationsInterface).Store(&owner); err != nil {
		return "", errors.Wrap(err, "unable to get notification server owner")
	}
	return owner, nil
}

func isNameHasNoOwnerError(err error) bool {
	var dbusError dbus.Error
	return errors.As(err, &dbusError) && dbusError.Name == nameHasNoOwnerError
}

func sendNotification(conn *dbus.Conn, owner string, notification notify.Notification) (uint32, error) {
	actions := make([]string, 0, len(notification.Actions)*2)
	for _, action := range notification.Actions {
		actions = append(actions, action.Key, action.Label)
	}

	call := conn.Object(owner, notificationsPath).Call(
		notificationsInterface+".Notify",
		0,
		notification.AppName,
		notification.ReplacesID,
		notification.AppIcon,
		notification.Summary,
		notification.Body,
		actions,
		notification.Hints,
		int32(notification.ExpireTimeout.Milliseconds()),
	)
	if call.Err != nil {
		return 0, errors.Wrap(call.Err, "unable to send notification")
	}

	var id uint32
	if err := call.Store(&id); err != nil {
		return 0, errors.Wrap(err, "unable to read notification ID")
	}
	return id, nil
}

func closeNotification(conn *dbus.Conn, owner string, id uint32) error {
	call := conn.Object(owner, notificationsPath).Call(notificationsInterface+".CloseNotification", 0, id)
	return errors.Wrap(call.Err, "unable to close notification")
}

func reconnectDBus(conn *dbus.Conn, reference *notificationReference) (*dbus.Conn, chan *dbus.Signal, error) {
	*reference = notificationReference{}
	conn.Close()
	return connectDBus()
}

func connectDBus() (*dbus.Conn, chan *dbus.Signal, error) {
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

	if err := conn.AddMatchSignal(
		dbus.WithMatchObjectPath(notificationsPath),
		dbus.WithMatchInterface(notificationsInterface),
		dbus.WithMatchMember("NotificationClosed"),
	); err != nil {
		conn.Close()
		return nil, nil, errors.Wrap(err, "unable to subscribe to notification signals")
	}

	signals := make(chan *dbus.Signal, 10)
	conn.Signal(signals)
	return conn, signals, nil
}
