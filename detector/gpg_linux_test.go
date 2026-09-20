package detector

import (
	"bufio"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/maximbaz/yubikey-touch-detector/notifier"
)

func testGPGTracker(t *testing.T, delay time.Duration) (*gpgOperationTracker, chan notifier.Message) {
	t.Helper()
	messages := make(chan notifier.Message, 16)
	notifiers := &sync.Map{}
	notifiers.Store("test", messages)
	return newGPGOperationTracker(newGPGNotifications(notifiers), delay), messages
}

func expectGPGMessage(t *testing.T, messages chan notifier.Message, expected notifier.Message, timeout time.Duration) {
	t.Helper()
	select {
	case actual := <-messages:
		if actual != expected {
			t.Fatalf("got %q, expected %q", actual, expected)
		}
	case <-time.After(timeout):
		t.Fatalf("timed out waiting for %q", expected)
	}
}

func expectNoGPGMessage(t *testing.T, messages chan notifier.Message, timeout time.Duration) {
	t.Helper()
	select {
	case actual := <-messages:
		t.Fatalf("unexpected message %q", actual)
	case <-time.After(timeout):
	}
}

func TestGPGNotificationsAggregateSources(t *testing.T) {
	messages := make(chan notifier.Message, 4)
	notifiers := &sync.Map{}
	notifiers.Store("test", messages)
	notifications := newGPGNotifications(notifiers)

	notifications.set(gpgProxySource, true)
	expectGPGMessage(t, messages, notifier.GPG_ON, 50*time.Millisecond)
	notifications.set(gpgBusyCheckSource, true)
	expectNoGPGMessage(t, messages, 10*time.Millisecond)
	notifications.set(gpgProxySource, false)
	expectNoGPGMessage(t, messages, 10*time.Millisecond)
	notifications.set(gpgBusyCheckSource, false)
	expectGPGMessage(t, messages, notifier.GPG_OFF, 50*time.Millisecond)
}

func TestGPGNotificationDeliveryCoalescesToLatestState(t *testing.T) {
	output := make(chan notifier.Message, 1)
	delivery := &gpgNotificationDelivery{
		output:  output,
		updates: make(chan notifier.Message, 1),
	}

	delivery.send(notifier.GPG_ON)
	delivery.send(notifier.GPG_OFF)
	go delivery.run()

	expectGPGMessage(t, output, notifier.GPG_OFF, 50*time.Millisecond)
	expectNoGPGMessage(t, output, 10*time.Millisecond)
}

func TestGPGNotificationsDoNotBlockOnStalledNotifier(t *testing.T) {
	stalled := make(chan notifier.Message)
	notifiers := &sync.Map{}
	notifiers.Store("stalled", stalled)
	notifications := newGPGNotifications(notifiers)

	done := make(chan struct{})
	go func() {
		for index := 0; index < 100; index++ {
			notifications.set(gpgProxySource, index%2 == 0)
		}
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(100 * time.Millisecond):
		t.Fatal("notifications blocked on a stalled notifier")
	}

	for {
		select {
		case message := <-stalled:
			if message == notifier.GPG_OFF {
				return
			}
		case <-time.After(50 * time.Millisecond):
			t.Fatal("stalled notifier did not receive the latest state")
		}
	}
}

func TestAssuanLineParserHandlesFragments(t *testing.T) {
	parser := &assuanLineParser{}
	var lines []string
	parser.feed([]byte("SIG"), func(line string) { lines = append(lines, line) })
	parser.feed([]byte("KEY ABC\r\nPKSIGN\nPART"), func(line string) { lines = append(lines, line) })
	parser.feed([]byte("IAL\n"), func(line string) { lines = append(lines, line) })

	expected := []string{"SIGKEY ABC", "PKSIGN", "PARTIAL"}
	if len(lines) != len(expected) {
		t.Fatalf("got %v, expected %v", lines, expected)
	}
	for index := range expected {
		if lines[index] != expected[index] {
			t.Fatalf("got %v, expected %v", lines, expected)
		}
	}
}

func TestGPGTrackerTimesOnlyQueueHead(t *testing.T) {
	tracker, messages := testGPGTracker(t, 100*time.Millisecond)
	first := tracker.start()
	second := tracker.start()

	time.Sleep(60 * time.Millisecond)
	tracker.finish(first)
	expectNoGPGMessage(t, messages, 60*time.Millisecond)
	expectGPGMessage(t, messages, notifier.GPG_ON, 80*time.Millisecond)
	tracker.finish(second)
	expectGPGMessage(t, messages, notifier.GPG_OFF, 50*time.Millisecond)
}

func TestGPGTrackerPausesForInquiry(t *testing.T) {
	tracker, messages := testGPGTracker(t, 40*time.Millisecond)
	state := &gpgAgentConnectionState{
		tracker:  tracker,
		cardKeys: map[string]bool{"ABC": true},
	}

	state.handleClientLine("SETKEY ABC")
	state.handleClientLine("PKDECRYPT")
	state.handleServerLine("INQUIRE CIPHERTEXT")
	expectNoGPGMessage(t, messages, 70*time.Millisecond)
	state.handleClientLine("END")
	expectGPGMessage(t, messages, notifier.GPG_ON, 70*time.Millisecond)
	state.handleServerLine("OK")
	expectGPGMessage(t, messages, notifier.GPG_OFF, 50*time.Millisecond)
}

func TestGPGConnectionIgnoresNonCardKey(t *testing.T) {
	tracker, messages := testGPGTracker(t, 20*time.Millisecond)
	state := &gpgAgentConnectionState{
		tracker:  tracker,
		cardKeys: map[string]bool{"ABC": true},
	}

	state.handleClientLine("SIGKEY ABC")
	state.handleClientLine("SIGKEY DEF")
	state.handleClientLine("PKSIGN")
	expectNoGPGMessage(t, messages, 50*time.Millisecond)
}

func TestGPGConnectionHandlesSetKeyOptions(t *testing.T) {
	tracker, messages := testGPGTracker(t, 20*time.Millisecond)
	state := &gpgAgentConnectionState{
		tracker:  tracker,
		cardKeys: map[string]bool{"ABC": true},
	}

	state.handleClientLine("SETKEY --force ABC")
	state.handleClientLine("PKDECRYPT")
	expectGPGMessage(t, messages, notifier.GPG_ON, 50*time.Millisecond)
	state.handleServerLine("OK")
	expectGPGMessage(t, messages, notifier.GPG_OFF, 50*time.Millisecond)
}

func TestGPGConnectionPausesForPinentryStatus(t *testing.T) {
	tracker, messages := testGPGTracker(t, 20*time.Millisecond)
	state := &gpgAgentConnectionState{
		tracker:  tracker,
		cardKeys: map[string]bool{"ABC": true},
	}
	process := exec.Command("sleep", "0.1")
	if err := process.Start(); err != nil {
		t.Fatal(err)
	}

	state.handleClientLine("SIGKEY ABC")
	state.handleClientLine("PKSIGN")
	state.handleServerLine("S PINENTRY_LAUNCHED " + strconv.Itoa(process.Process.Pid))
	expectNoGPGMessage(t, messages, 50*time.Millisecond)
	if err := process.Wait(); err != nil {
		t.Fatal(err)
	}
	expectGPGMessage(t, messages, notifier.GPG_ON, 100*time.Millisecond)
	state.handleServerLine("OK")
	expectGPGMessage(t, messages, notifier.GPG_OFF, 50*time.Millisecond)
}

func TestGPGConnectionPausesForPinentryInquiry(t *testing.T) {
	tracker, messages := testGPGTracker(t, 20*time.Millisecond)
	state := &gpgAgentConnectionState{
		tracker:  tracker,
		cardKeys: map[string]bool{"ABC": true},
	}
	process := exec.Command("sleep", "0.1")
	if err := process.Start(); err != nil {
		t.Fatal(err)
	}

	state.handleClientLine("SIGKEY ABC")
	state.handleClientLine("PKSIGN")
	state.handleServerLine("INQUIRE PINENTRY_LAUNCHED " + strconv.Itoa(process.Process.Pid))
	state.handleClientLine("END")
	expectNoGPGMessage(t, messages, 50*time.Millisecond)
	if err := process.Wait(); err != nil {
		t.Fatal(err)
	}
	expectGPGMessage(t, messages, notifier.GPG_ON, 100*time.Millisecond)
	state.handleServerLine("OK")
	expectGPGMessage(t, messages, notifier.GPG_OFF, 50*time.Millisecond)
}

func TestGPGConnectionKeepsSigningKey(t *testing.T) {
	tracker, messages := testGPGTracker(t, 20*time.Millisecond)
	state := &gpgAgentConnectionState{
		tracker:  tracker,
		cardKeys: map[string]bool{"ABC": true},
	}

	state.handleClientLine("SIGKEY ABC")
	state.handleClientLine("PKSIGN")
	expectGPGMessage(t, messages, notifier.GPG_ON, 50*time.Millisecond)
	state.handleServerLine("OK")
	expectGPGMessage(t, messages, notifier.GPG_OFF, 50*time.Millisecond)

	state.handleClientLine("PKSIGN")
	expectGPGMessage(t, messages, notifier.GPG_ON, 50*time.Millisecond)
	state.handleServerLine("OK")
	expectGPGMessage(t, messages, notifier.GPG_OFF, 50*time.Millisecond)
}

func TestGPGProxyForwardsAndRestoresSocket(t *testing.T) {
	publicPath := filepath.Join(t.TempDir(), "S.gpg-agent")
	address, err := net.ResolveUnixAddr("unix", publicPath)
	if err != nil {
		t.Fatal(err)
	}
	backendListener, err := net.ListenUnix("unix", address)
	if err != nil {
		t.Fatal(err)
	}
	defer backendListener.Close()

	tracker, _ := testGPGTracker(t, time.Second)
	session, err := installGPGProxy(publicPath, tracker, map[string]bool{})
	if err != nil {
		t.Fatal(err)
	}
	probe, err := backendListener.AcceptUnix()
	if err != nil {
		t.Fatal(err)
	}
	probe.Close()
	acceptResult := make(chan error, 1)
	go func() { acceptResult <- session.accept() }()

	client, err := net.Dial("unix", publicPath)
	if err != nil {
		t.Fatal(err)
	}
	backend, err := backendListener.AcceptUnix()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := backend.Write([]byte("OK hello\n")); err != nil {
		t.Fatal(err)
	}
	line, err := bufio.NewReader(client).ReadString('\n')
	if err != nil || line != "OK hello\n" {
		t.Fatalf("got %q and %v", line, err)
	}
	client.Close()
	backend.Close()
	session.close(true)
	<-acceptResult

	restored, err := net.Dial("unix", publicPath)
	if err != nil {
		t.Fatalf("restored socket is unavailable: %v", err)
	}
	restored.Close()
}

func TestGPGProxyDoesNotOverwriteReplacementSocket(t *testing.T) {
	publicPath := filepath.Join(t.TempDir(), "S.gpg-agent")
	address, err := net.ResolveUnixAddr("unix", publicPath)
	if err != nil {
		t.Fatal(err)
	}
	backendListener, err := net.ListenUnix("unix", address)
	if err != nil {
		t.Fatal(err)
	}
	defer backendListener.Close()

	tracker, _ := testGPGTracker(t, time.Second)
	session, err := installGPGProxy(publicPath, tracker, map[string]bool{})
	if err != nil {
		t.Fatal(err)
	}
	probe, err := backendListener.AcceptUnix()
	if err != nil {
		t.Fatal(err)
	}
	probe.Close()
	if err := os.Remove(publicPath); err != nil {
		t.Fatal(err)
	}
	replacement, err := net.ListenUnix("unix", address)
	if err != nil {
		t.Fatal(err)
	}
	defer replacement.Close()

	session.close(true)
	connection, err := net.Dial("unix", publicPath)
	if err != nil {
		t.Fatalf("replacement socket was overwritten: %v", err)
	}
	connection.Close()
}

func TestShadowedKeygrips(t *testing.T) {
	files := []string{
		filepath.Join("home", "private-keys-v1.d", "abcdef.key"),
		filepath.Join("home", "private-keys-v1.d", "123456.key"),
	}
	keygrips := shadowedKeygrips(files)
	if !keygrips["ABCDEF"] || !keygrips["123456"] || len(keygrips) != 2 {
		t.Fatalf("unexpected keygrips: %v", keygrips)
	}
}
