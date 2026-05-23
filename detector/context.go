package detector

import (
	"fmt"
	"net"
	"os"
	"os/exec"
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

// gpgContextExcluded lists background daemons that should not be reported
// as the triggering process even when they are connected to gpg-agent.
var gpgContextExcluded = map[string]bool{
	"gpg-agent": true,
	"scdaemon":  true,
}

// unixSocketPeerMap parses `ss -xpn` output to build a map from each Unix
// socket's inode to its connected peer's inode.
//
// ss output format (one line per socket endpoint):
//
//	u_str ESTAB 0 0  <local-addr> <local-inode>  <peer-addr> <peer-inode>  [users:(...)]
//
// Both the local and peer inode appear at fixed field offsets (indices 5 and 7)
// regardless of whether the address field is "*" or a socket path.
func unixSocketPeerMap() (map[uint32]uint32, error) {
	out, err := exec.Command("ss", "-xpn", "--no-header").Output()
	if err != nil {
		return nil, fmt.Errorf("ss: %w", err)
	}

	result := make(map[uint32]uint32)
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 8 {
			continue
		}
		localIno, err1 := strconv.ParseUint(fields[5], 10, 32)
		peerIno, err2 := strconv.ParseUint(fields[7], 10, 32)
		if err1 != nil || err2 != nil || localIno == 0 || peerIno == 0 {
			continue
		}
		result[uint32(localIno)] = uint32(peerIno)
	}
	return result, nil
}

// findGPGContext identifies all non-daemon processes currently connected to
// gpg-agent by tracing Unix socket peer inodes.
// Returns one command line per caller, joined by newlines; empty if none found.
func findGPGContext() string {
	peerMap, err := unixSocketPeerMap()
	if err != nil {
		return ""
	}

	// Single /proc scan: build inode→pid for every process, and record which
	// socket inodes belong to gpg-agent.
	inodeToPID := map[uint32]int32{}
	gpgAgentInodes := map[uint32]bool{}

	entries, err := os.ReadDir("/proc")
	if err != nil {
		return ""
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}

		comm, _ := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
		isGPGAgent := strings.TrimSpace(string(comm)) == "gpg-agent"

		fds, err := os.ReadDir(fmt.Sprintf("/proc/%d/fd", pid))
		if err != nil {
			continue
		}
		for _, fd := range fds {
			link, err := os.Readlink(fmt.Sprintf("/proc/%d/fd/%s", pid, fd.Name()))
			if err != nil {
				continue
			}
			var inode uint32
			if _, err := fmt.Sscanf(link, "socket:[%d]", &inode); err != nil {
				continue
			}
			inodeToPID[inode] = int32(pid)
			if isGPGAgent {
				gpgAgentInodes[inode] = true
			}
		}
	}

	// For each of gpg-agent's sockets, look up the peer inode and find which
	// process owns it.
	var results []string
	seen := map[int32]bool{}
	for agentInode := range gpgAgentInodes {
		peerInode, ok := peerMap[agentInode]
		if !ok || peerInode == 0 {
			continue
		}
		clientPID, ok := inodeToPID[peerInode]
		if !ok || seen[clientPID] {
			continue
		}
		seen[clientPID] = true

		cmdline := getProcessCmdline(clientPID)
		if cmdline == "" {
			continue
		}
		fields := strings.Fields(cmdline)
		if gpgContextExcluded[path.Base(fields[0])] {
			continue
		}
		results = append(results, cmdline)
	}

	return strings.Join(results, "\n")
}
