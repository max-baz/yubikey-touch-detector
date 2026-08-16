package notifier

import (
	"errors"
	"fmt"
	"testing"

	"github.com/godbus/dbus/v5"
)

func TestIsNameHasNoOwnerError(t *testing.T) {
	noOwner := dbus.Error{Name: nameHasNoOwnerError}
	for name, test := range map[string]struct {
		err  error
		want bool
	}{
		"matching":    {err: noOwner, want: true},
		"wrapped":     {err: fmt.Errorf("wrapped: %w", noOwner), want: true},
		"other D-Bus": {err: dbus.Error{Name: "org.freedesktop.DBus.Error.Failed"}},
		"other error": {err: errors.New("failed")},
	} {
		t.Run(name, func(t *testing.T) {
			if got := isNameHasNoOwnerError(test.err); got != test.want {
				t.Fatalf("isNameHasNoOwnerError() = %t, want %t", got, test.want)
			}
		})
	}
}

func TestNotificationReferenceIsScopedToOwner(t *testing.T) {
	reference := notificationReference{owner: ":1.10", id: 42}

	reference.useOwner(":1.10")
	if reference.id != 42 {
		t.Fatalf("same owner changed ID to %d, want 42", reference.id)
	}

	reference.useOwner(":1.11")
	if reference.id != 0 {
		t.Fatalf("changed owner left stale ID %d, want 0", reference.id)
	}
	if reference.owner != ":1.11" {
		t.Fatalf("owner is %q, want %q", reference.owner, ":1.11")
	}
}

func TestNotificationReferenceHandlesClosedSignal(t *testing.T) {
	owner := ":1.10"
	closed := &dbus.Signal{
		Sender: owner,
		Name:   notificationsClosedSignal,
		Body:   []interface{}{uint32(42), uint32(2)},
	}

	for name, signal := range map[string]*dbus.Signal{
		"matching":    closed,
		"other owner": {Sender: ":1.11", Name: closed.Name, Body: closed.Body},
		"other ID":    {Sender: closed.Sender, Name: closed.Name, Body: []interface{}{uint32(43), uint32(2)}},
	} {
		t.Run(name, func(t *testing.T) {
			reference := notificationReference{owner: owner, id: 42}
			reference.handleSignal(signal)
			if name == "matching" && reference.id != 0 {
				t.Fatalf("matching close left ID %d, want 0", reference.id)
			}
			if name != "matching" && reference.id != 42 {
				t.Fatalf("unrelated close changed ID to %d, want 42", reference.id)
			}
		})
	}
}
