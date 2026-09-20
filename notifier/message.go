package notifier

import (
	"sort"
	"strings"
)

type Message string

// All messages have a fixed length of 5 chars to simplify code on the receiving side
const (
	GPG_ON   Message = "GPG_1"
	GPG_OFF  Message = "GPG_0"
	U2F_ON   Message = "U2F_1"
	U2F_OFF  Message = "U2F_0"
	HMAC_ON  Message = "MAC_1"
	HMAC_OFF Message = "MAC_0"
)

type touchState struct {
	active map[string]bool
}

func newTouchState() *touchState {
	return &touchState{active: make(map[string]bool)}
}

func (state *touchState) update(message Message) (bool, bool, bool) {
	wasActive := len(state.active) > 0
	var reason string
	var active bool
	switch message {
	case GPG_ON:
		reason, active = "gpg", true
	case GPG_OFF:
		reason = "gpg"
	case U2F_ON:
		reason, active = "u2f", true
	case U2F_OFF:
		reason = "u2f"
	case HMAC_ON:
		reason, active = "hmac", true
	case HMAC_OFF:
		reason = "hmac"
	default:
		return wasActive, wasActive, false
	}
	wasReasonActive := state.active[reason]
	if active {
		state.active[reason] = true
	} else {
		delete(state.active, reason)
	}
	return wasActive, len(state.active) > 0, wasReasonActive != active
}

func (state *touchState) reasons() string {
	reasons := make([]string, 0, len(state.active))
	for reason := range state.active {
		reasons = append(reasons, reason)
	}
	sort.Strings(reasons)
	return strings.Join(reasons, ", ")
}
