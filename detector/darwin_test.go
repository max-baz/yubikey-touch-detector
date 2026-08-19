//go:build darwin

package detector

import (
	"reflect"
	"testing"

	"github.com/maximbaz/yubikey-touch-detector/notifier"
)

func TestMacOSFIDOMessages(t *testing.T) {
	state := macOSTouchState{
		fidoClients:   make(map[string]bool),
		activeClients: make(map[string]bool),
		isYubico:      func(device string) bool { return device == "0x1" },
	}
	entries := []macOSLogEntry{
		{ProcessImagePath: "/kernel", SenderImagePath: "IOHIDFamily", EventMessage: "AppleUSBTopCaseHIDDriver:0x1 open by IOHIDLibUserClient:0x2 (0x1)"},
		{ProcessImagePath: "/kernel", SenderImagePath: "IOHIDFamily", EventMessage: "IOHIDLibUserClient:0x2 startQueue"},
		{ProcessImagePath: "/kernel", SenderImagePath: "IOHIDFamily", EventMessage: "AppleUserUSBHostHIDDevice:0x1 open by IOHIDLibUserClient:0x3 (0x1)"},
		{ProcessImagePath: "/kernel", SenderImagePath: "IOHIDFamily", EventMessage: "IOHIDLibUserClient:0x3 startQueue"},
		{ProcessImagePath: "/kernel", SenderImagePath: "IOHIDFamily", EventMessage: "IOHIDLibUserClient:0x3 startQueue"},
		{ProcessImagePath: "/kernel", SenderImagePath: "IOHIDFamily", EventMessage: "IOHIDLibUserClient:0x3 stopQueue"},
	}
	var messages []notifier.Message
	for _, entry := range entries {
		messages = append(messages, state.messages(entry)...)
	}
	want := []notifier.Message{notifier.U2F_ON, notifier.U2F_OFF}
	if !reflect.DeepEqual(messages, want) {
		t.Fatalf("messages = %v, want %v", messages, want)
	}
}

func TestParseYubicoDevices(t *testing.T) {
	output := `+-o AppleUserUSBHostHIDDevice  <class AppleUserHIDDevice, id 0x100000001, registered>
    "VendorID" = 0x1234
+-o AppleUserUSBHostHIDDevice  <class AppleUserHIDDevice, id 0x100000002, registered>
    "VendorID" = 0x1050`
	want := map[string]bool{"0x100000001": false, "0x100000002": true}
	if got := parseYubicoDevices(output); !reflect.DeepEqual(got, want) {
		t.Fatalf("devices = %v, want %v", got, want)
	}
}

func TestMacOSOpenPGPMessages(t *testing.T) {
	state := macOSTouchState{
		fidoClients:   make(map[string]bool),
		activeClients: make(map[string]bool),
		isYubico:      func(string) bool { return false },
	}
	entry := macOSLogEntry{ProcessImagePath: "/usr/libexec/usbsmartcardreaderd", Subsystem: "com.apple.CryptoTokenKit", EventMessage: "Time extension received"}
	if got := state.messages(entry); !reflect.DeepEqual(got, []notifier.Message{notifier.GPG_ON}) {
		t.Fatalf("start messages = %v", got)
	}
	if got := state.messages(entry); got != nil {
		t.Fatalf("duplicate messages = %v", got)
	}
	entry.EventMessage = "Card response received"
	if got := state.messages(entry); !reflect.DeepEqual(got, []notifier.Message{notifier.GPG_OFF}) {
		t.Fatalf("stop messages = %v", got)
	}
}
