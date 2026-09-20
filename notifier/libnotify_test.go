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

func TestTouchStateIsIdempotentAndTracksReasons(t *testing.T) {
	state := newTouchState()
	steps := []struct {
		message Message
		before  bool
		after   bool
		changed bool
		reasons string
	}{
		{U2F_ON, false, true, true, "u2f"},
		{U2F_ON, true, true, false, "u2f"},
		{HMAC_ON, true, true, true, "hmac, u2f"},
		{U2F_OFF, true, true, true, "hmac"},
		{U2F_OFF, true, true, false, "hmac"},
		{HMAC_OFF, true, false, true, ""},
		{HMAC_OFF, false, false, false, ""},
	}
	for _, step := range steps {
		before, after, changed := state.update(step.message)
		if before != step.before || after != step.after || changed != step.changed {
			t.Fatalf("update(%q) = %t, %t, %t, want %t, %t, %t", step.message, before, after, changed, step.before, step.after, step.changed)
		}
		if reasons := state.reasons(); reasons != step.reasons {
			t.Fatalf("reasons after update(%q) = %q, want %q", step.message, reasons, step.reasons)
		}
	}
}

func TestNotificationTemplates(t *testing.T) {
	templates, err := newNotificationTemplates("Touch required: {{.Reasons}}", "Reasons: {{.Reasons}}")
	if err != nil {
		t.Fatal(err)
	}
	title, body, err := templates.render("gpg, u2f")
	if err != nil {
		t.Fatal(err)
	}
	if title != "Touch required: gpg, u2f" || body != "Reasons: gpg, u2f" {
		t.Fatalf("render() = %q, %q", title, body)
	}
}

func TestDefaultNotificationBodyIncludesReasons(t *testing.T) {
	templates, err := newNotificationTemplates(DefaultNotificationTitle, DefaultNotificationBody)
	if err != nil {
		t.Fatal(err)
	}
	_, body, err := templates.render("gpg")
	if err != nil {
		t.Fatal(err)
	}
	if body != "Touch your YubiKey to continue (gpg)." {
		t.Fatalf("default body = %q", body)
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
