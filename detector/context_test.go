package detector

import (
	"fmt"
	"net"
	"os"
	"strings"
	"testing"
)

func TestGetProcessCmdline(t *testing.T) {
	// Use our own PID — /proc/<pid>/cmdline is always available.
	pid := int32(os.Getpid())
	cmdline := getProcessCmdline(pid)
	if cmdline == "" {
		t.Fatal("expected non-empty cmdline for current process")
	}
	// The test binary name should appear somewhere in argv[0].
	if !strings.Contains(cmdline, "context") && !strings.Contains(cmdline, "test") {
		t.Errorf("unexpected cmdline %q — expected it to contain the test binary name", cmdline)
	}
}

func TestGetProcessCmdline_InvalidPID(t *testing.T) {
	if got := getProcessCmdline(0); got != "" {
		t.Errorf("expected empty string for pid 0, got %q", got)
	}
	if got := getProcessCmdline(-1); got != "" {
		t.Errorf("expected empty string for pid -1, got %q", got)
	}
	// PID 2^30 is extremely unlikely to exist.
	if got := getProcessCmdline(1 << 30); got != "" {
		t.Errorf("expected empty string for non-existent pid, got %q", got)
	}
}

func TestGetPeerProcessCmdline(t *testing.T) {
	// Set up a Unix socket pair so we can call getPeerProcessCmdline.
	dir := t.TempDir()
	socketPath := fmt.Sprintf("%s/test.sock", dir)

	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal("listen:", err)
	}
	defer ln.Close()

	connCh := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err == nil {
			connCh <- c
		}
	}()

	client, err := net.Dial("unix", socketPath)
	if err != nil {
		t.Fatal("dial:", err)
	}
	defer client.Close()

	server := <-connCh
	defer server.Close()

	// From the server side, the peer is this test process.
	result := getPeerProcessCmdline(server)
	if result == "" {
		t.Fatal("expected non-empty peer cmdline")
	}
	if !strings.Contains(result, "context") && !strings.Contains(result, "test") {
		t.Errorf("unexpected peer cmdline %q", result)
	}
}

func TestGetPeerProcessCmdline_NonUnixConn(t *testing.T) {
	// A TCP connection is not a Unix socket; should return "".
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	connCh := make(chan net.Conn, 1)
	go func() {
		c, _ := ln.Accept()
		connCh <- c
	}()

	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	server := <-connCh
	defer server.Close()

	if got := getPeerProcessCmdline(server); got != "" {
		t.Errorf("expected empty string for TCP conn, got %q", got)
	}
}

func TestFindGPGContext(t *testing.T) {
	// findGPGContext scans /proc.  We cannot guarantee a GPG process is running,
	// but we can verify it returns a string (possibly empty) without panicking.
	result := findGPGContext()
	// If the test binary itself matched a candidate name this would be non-empty,
	// but "context.test" does not match any candidate — so we just check no panic.
	_ = result
}

func TestFindGPGContext_ExcludesDaemons(t *testing.T) {
	// Verify that gpgContextExcluded contains the expected daemon names.
	for _, daemon := range []string{"gpg-agent", "scdaemon"} {
		if !gpgContextExcluded[daemon] {
			t.Errorf("expected %q to be in gpgContextExcluded", daemon)
		}
	}
}

func TestFindGPGContext_CandidateList(t *testing.T) {
	// Verify that the candidate list contains the expected program names.
	expected := []string{"gpg", "git", "ssh", "pass"}
	for _, name := range expected {
		found := false
		for _, cand := range gpgContextCandidates {
			if cand == name {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected %q to be in gpgContextCandidates", name)
		}
	}
}
