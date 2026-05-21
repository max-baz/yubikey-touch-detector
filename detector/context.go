package detector

import (
	"fmt"
	"net"
	"os"
	"path"
	"strconv"
	"strings"
	"syscall"
)

// getProcessCmdline returns the command line of a process given its PID,
// with NUL separators replaced by spaces.
func getProcessCmdline(pid int32) string {
	if pid <= 0 {
		return ""
	}
	cmdlineBytes, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil || len(cmdlineBytes) == 0 {
		return ""
	}
	cmdline := strings.TrimRight(string(cmdlineBytes), "\x00")
	return strings.Join(strings.Split(cmdline, "\x00"), " ")
}

// getPeerProcessCmdline returns the command line of the process on the other
// end of a Unix socket connection, using SO_PEERCRED.
func getPeerProcessCmdline(conn net.Conn) string {
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return ""
	}
	raw, err := unixConn.SyscallConn()
	if err != nil {
		return ""
	}
	var pid int32
	_ = raw.Control(func(fd uintptr) {
		ucred, e := syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
		if e == nil {
			pid = ucred.Pid
		}
	})
	return getProcessCmdline(pid)
}

// gpgContextCandidates lists program names (matched against argv[0] basename)
// that are likely to be the user-facing process triggering a GPG/SSH operation.
var gpgContextCandidates = []string{
	"gpg", "gpg2", "pass", "git", "ssh", "ansible", "ansible-playbook",
}

// gpgContextExcluded lists background daemons that should not be reported
// as the triggering process.
var gpgContextExcluded = map[string]bool{
	"gpg-agent": true,
	"scdaemon":  true,
}

// findGPGContext scans /proc for a likely user-facing process that triggered
// a GPG or SSH operation.  This is best-effort: a concurrent unrelated process
// with a matching name may be returned instead.
func findGPGContext() string {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return ""
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		if _, err := strconv.Atoi(entry.Name()); err != nil {
			continue
		}
		cmdlineBytes, err := os.ReadFile(fmt.Sprintf("/proc/%s/cmdline", entry.Name()))
		if err != nil || len(cmdlineBytes) == 0 {
			continue
		}
		cmdline := strings.TrimRight(string(cmdlineBytes), "\x00")
		fields := strings.Split(cmdline, "\x00")
		progName := path.Base(fields[0])
		if gpgContextExcluded[progName] {
			continue
		}
		for _, cand := range gpgContextCandidates {
			if progName == cand {
				return strings.Join(fields, " ")
			}
		}
	}
	return ""
}
