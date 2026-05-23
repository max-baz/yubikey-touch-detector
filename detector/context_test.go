package detector

import (
	"fmt"
	"net"
	"os"
	"strings"
	"syscall"
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

// socketInode returns the inode number of the underlying socket fd.
func socketInode(t *testing.T, conn net.Conn) uint32 {
	t.Helper()
	raw, err := conn.(*net.UnixConn).SyscallConn()
	if err != nil {
		t.Fatal("SyscallConn:", err)
	}
	var inode uint32
	_ = raw.Control(func(fd uintptr) {
		var st syscall.Stat_t
		if err := syscall.Fstat(int(fd), &st); err == nil {
			inode = uint32(st.Ino)
		}
	})
	if inode == 0 {
		t.Fatal("could not determine socket inode")
	}
	return inode
}

func TestUnixSocketPeerMap(t *testing.T) {
	// Create a connected Unix socket pair so we have a known pair to look for.
	dir := t.TempDir()
	ln, err := net.Listen("unix", dir+"/peer.sock")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	connCh := make(chan net.Conn, 1)
	go func() {
		c, _ := ln.Accept()
		connCh <- c
	}()

	client, err := net.Dial("unix", dir+"/peer.sock")
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	server := <-connCh
	defer server.Close()

	clientInode := socketInode(t, client)
	serverInode := socketInode(t, server)

	peerMap, err := unixSocketPeerMap()
	if err != nil {
		t.Fatal("unixSocketPeerMap:", err)
	}
	if len(peerMap) == 0 {
		t.Fatal("expected non-empty peer map")
	}

	// Both ends of our socket pair must appear in the map and point at each other.
	if got := peerMap[clientInode]; got != serverInode {
		t.Errorf("peerMap[client inode %d] = %d, want %d", clientInode, got, serverInode)
	}
	if got := peerMap[serverInode]; got != clientInode {
		t.Errorf("peerMap[server inode %d] = %d, want %d", serverInode, got, clientInode)
	}
}

func TestFindGPGContext(t *testing.T) {
	// We cannot guarantee gpg-agent is running, but the function must not panic
	// and must return something sensible (empty string when no gpg-agent).
	result := findGPGContext()
	_ = result
}

func TestFindGPGContext_ExcludesDaemons(t *testing.T) {
	for _, daemon := range []string{"gpg-agent", "scdaemon"} {
		if !gpgContextExcluded[daemon] {
			t.Errorf("expected %q to be in gpgContextExcluded", daemon)
		}
	}
}
