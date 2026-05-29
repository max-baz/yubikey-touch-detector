package detector

import (
	"fmt"
	"sync"
	"testing"

	"github.com/proglottis/gpgme"
)

func TestCheckGPGOnRequest_FactoryErrorExitsCleanly(t *testing.T) {
	ch := make(chan string)
	close(ch) // No requests; loop exits immediately after factory fails.

	callCount := 0
	factory := func() (*gpgme.Context, error) {
		callCount++
		return nil, fmt.Errorf("simulated gpg-agent unavailable")
	}

	var notifiers sync.Map
	CheckGPGOnRequest(ch, &notifiers, factory)

	if callCount != 1 {
		t.Errorf("factory called %d times, want 1", callCount)
	}
}
