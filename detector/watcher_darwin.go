package detector

import (
	"bufio"
	"encoding/json"
	"os/exec"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/maximbaz/yubikey-touch-detector/notifier"
)

const macOSLogPredicate = `(processImagePath == "/kernel" AND senderImagePath ENDSWITH "IOHIDFamily") OR (subsystem CONTAINS "CryptoTokenKit")`

type macOSLogEntry struct {
	ProcessImagePath string `json:"processImagePath"`
	SenderImagePath  string `json:"senderImagePath"`
	Subsystem        string `json:"subsystem"`
	EventMessage     string `json:"eventMessage"`
}

type macOSTouchState struct {
	fidoClients   map[string]bool
	activeClients map[string]bool
	isYubico      func(string) bool
	openPGP       bool
}

type macOSDeviceRegistry struct {
	checkedAt time.Time
	devices   map[string]bool
}

func WatchMacOS(notifiers *sync.Map) {
	cmd := exec.Command("log", "stream", "--level", "debug", "--style", "ndjson", "--predicate", macOSLogPredicate)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		log.Error("Cannot read macOS unified log: ", err)
		return
	}
	if err := cmd.Start(); err != nil {
		log.Error("Cannot start macOS unified log stream: ", err)
		return
	}
	defer cmd.Process.Kill()

	registry := macOSDeviceRegistry{}
	state := macOSTouchState{
		fidoClients:   make(map[string]bool),
		activeClients: make(map[string]bool),
		isYubico:      registry.isYubico,
	}
	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		var entry macOSLogEntry
		if json.Unmarshal(scanner.Bytes(), &entry) != nil {
			continue
		}
		for _, message := range state.messages(entry) {
			notifiers.Range(func(_, value interface{}) bool {
				value.(chan notifier.Message) <- message
				return true
			})
		}
	}
	if err := scanner.Err(); err != nil {
		log.Error("Cannot read macOS unified log stream: ", err)
		return
	}
	if err := cmd.Wait(); err != nil {
		log.Error("macOS unified log stream stopped: ", err)
	}
}

func (state *macOSTouchState) messages(entry macOSLogEntry) []notifier.Message {
	if entry.ProcessImagePath == "/kernel" && strings.HasSuffix(entry.SenderImagePath, "IOHIDFamily") {
		message := entry.EventMessage
		if device, client, found := hidConnection(message, " open by "); found {
			state.fidoClients[client] = state.isYubico(device)
		}
		if _, client, found := hidConnection(message, " close by "); found {
			wasActive := state.activeClients[client]
			delete(state.activeClients, client)
			delete(state.fidoClients, client)
			if wasActive && len(state.activeClients) == 0 {
				return []notifier.Message{notifier.U2F_OFF}
			}
		}

		fields := strings.Fields(message)
		if len(fields) < 2 || !state.fidoClients[fields[0]] {
			return nil
		}
		client := fields[0]
		switch fields[len(fields)-1] {
		case "startQueue":
			wasInactive := len(state.activeClients) == 0
			state.activeClients[client] = true
			if wasInactive {
				return []notifier.Message{notifier.U2F_ON}
			}
		case "stopQueue":
			wasActive := state.activeClients[client]
			delete(state.activeClients, client)
			if wasActive && len(state.activeClients) == 0 {
				return []notifier.Message{notifier.U2F_OFF}
			}
		}
		return nil
	}

	if strings.HasSuffix(entry.ProcessImagePath, "usbsmartcardreaderd") && strings.HasSuffix(entry.Subsystem, "CryptoTokenKit") {
		needed := entry.EventMessage == "Time extension received"
		if needed != state.openPGP {
			state.openPGP = needed
			if needed {
				return []notifier.Message{notifier.GPG_ON}
			}
			return []notifier.Message{notifier.GPG_OFF}
		}
	}
	return nil
}

func hidConnection(message, separator string) (string, string, bool) {
	device, rest, found := strings.Cut(message, separator)
	if !found || !strings.HasPrefix(device, "AppleUserUSBHostHIDDevice:") {
		return "", "", false
	}
	client := strings.Fields(rest)
	if len(client) == 0 {
		return "", "", false
	}
	return strings.TrimPrefix(device, "AppleUserUSBHostHIDDevice:"), client[0], true
}

func (registry *macOSDeviceRegistry) isYubico(device string) bool {
	_, known := registry.devices[device]
	if !known || time.Since(registry.checkedAt) > 5*time.Second {
		output, err := exec.Command("ioreg", "-k", "VendorID", "-l", "-w0", "-x").Output()
		if err != nil {
			log.Warn("Cannot inspect macOS USB devices: ", err)
			return false
		}
		registry.devices = parseYubicoDevices(string(output))
		registry.checkedAt = time.Now()
	}
	return registry.devices[device]
}

func parseYubicoDevices(output string) map[string]bool {
	devices := make(map[string]bool)
	var device string
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		for i, field := range fields {
			if field == "id" && i+1 < len(fields) {
				device = strings.TrimSuffix(fields[i+1], ",")
				break
			}
		}
		if device != "" && strings.Contains(line, `"VendorID" = `) {
			devices[device] = strings.Contains(line, `"VendorID" = 0x1050`)
		}
	}
	return devices
}
