package notifier

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

// TouchEvent carries a touch notification together with optional human-readable
// context describing the process that triggered the request.
type TouchEvent struct {
	Type    Message
	Context string
}
