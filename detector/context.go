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

	log "github.com/sirupsen/logrus"
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
		log.Debug("getPeerProcessCmdline: connection is not a UnixConn")
		return ""
	}
	raw, err := unixConn.SyscallConn()
	if err != nil {
		log.Debugf("getPeerProcessCmdline: SyscallConn error: %v", err)
		return ""
	}
	var pid int32
	_ = raw.Control(func(fd uintptr) {
		ucred, e := syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
		if e == nil {
			pid = ucred.Pid
		} else {
			log.Debugf("getPeerProcessCmdline: GetsockoptUcred error: %v", e)
		}
	})
	log.Debugf("getPeerProcessCmdline: peer pid=%d", pid)
	result := getProcessCmdline(pid)
	log.Debugf("getPeerProcessCmdline: result=%q", result)
	return result
}

// gpgContextExcluded lists background daemons that should not be reported
// as the triggering process even when they are connected to gpg-agent.
var gpgContextExcluded = map[string]bool{
	"gpg-agent": true,
	"scdaemon":  true,
}

// ssSocketInfo holds per-socket data parsed from one line of `ss -xpn` output.
type ssSocketInfo struct {
	state     string // ESTAB, LISTEN, etc.
	localAddr string // local socket path, or "" if unnamed ("*")
	localIno  uint32
	peerIno   uint32
	pid       int32  // owning process PID from users field, 0 if not available
	procName  string // owning process name from users field, "" if not available
}

// parseSSSockets runs `ss -xpn` and returns one record per socket endpoint.
//
// ss output format (one line per endpoint, whitespace-separated):
//
//	<type> <state> <recv-q> <send-q> <local-addr> <local-inode> <peer-addr> <peer-inode> [users:(...)]
//
// The optional users field: users:(("name",pid=NNN,fd=M),...)
func parseSSSockets() ([]ssSocketInfo, error) {
	out, err := exec.Command("ss", "-xpn", "--no-header").Output()
	if err != nil {
		return nil, fmt.Errorf("ss: %w", err)
	}

	var sockets []ssSocketInfo
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 8 {
			continue
		}
		localIno, err1 := strconv.ParseUint(fields[5], 10, 32)
		peerIno, err2 := strconv.ParseUint(fields[7], 10, 32)
		if err1 != nil || err2 != nil || localIno == 0 {
			continue
		}
		localAddr := fields[4]
		if localAddr == "*" {
			localAddr = ""
		}
		sock := ssSocketInfo{
			state:     fields[1],
			localAddr: localAddr,
			localIno:  uint32(localIno),
			peerIno:   uint32(peerIno),
		}
		// Parse optional users field: users:(("name",pid=NNN,fd=M),...)
		for _, f := range fields[8:] {
			if !strings.HasPrefix(f, "users:") {
				continue
			}
			sock.procName = extractSSName(f)
			sock.pid = extractSSPID(f)
			break
		}
		sockets = append(sockets, sock)
	}
	return sockets, nil
}

// extractSSPID extracts the first pid value from a ss users field.
func extractSSPID(users string) int32 {
	idx := strings.Index(users, "pid=")
	if idx < 0 {
		return 0
	}
	rest := users[idx+4:]
	end := strings.IndexAny(rest, ",)")
	if end < 0 {
		end = len(rest)
	}
	p, err := strconv.ParseInt(rest[:end], 10, 32)
	if err != nil {
		return 0
	}
	return int32(p)
}

// extractSSName extracts the first process name from a ss users field.
func extractSSName(users string) string {
	// format: users:(("name",pid=NNN,fd=M),...)
	start := strings.Index(users, `users:(("`)
	if start < 0 {
		return ""
	}
	rest := users[start+9:]
	end := strings.Index(rest, `"`)
	if end < 0 {
		return ""
	}
	return rest[:end]
}

// unixSocketPeerMap returns a map from each Unix socket's local inode to its
// peer inode. Used by tests.
func unixSocketPeerMap() (map[uint32]uint32, error) {
	sockets, err := parseSSSockets()
	if err != nil {
		return nil, err
	}
	result := make(map[uint32]uint32, len(sockets))
	for _, s := range sockets {
		if s.peerIno != 0 {
			result[s.localIno] = s.peerIno
		}
	}
	return result, nil
}

// gpgAgentSocketPaths returns the set of Unix socket paths that gpg-agent
// listens on, queried via gpgconf.
func gpgAgentSocketPaths() map[string]bool {
	paths := map[string]bool{}
	for _, dir := range []string{"agent-socket", "agent-ssh-socket", "agent-extra-socket", "agent-browser-socket"} {
		out, err := exec.Command("gpgconf", "--list-dirs", dir).Output()
		if err != nil {
			continue
		}
		p := strings.TrimSpace(string(out))
		if p != "" {
			paths[p] = true
		}
	}
	return paths
}

// findGPGContext identifies processes connected to gpg-agent via ss output.
//
// In ss output for Unix sockets, the SERVER side of each accepted connection
// shows the socket file path as the LOCAL address (fields[4]), even though the
// accepted socket is anonymous.  The CLIENT side shows local=* but has a
// readable users field.  The algorithm:
//
//  1. Find ss records with state=ESTAB and local-addr matching a gpg-agent
//     socket path → those are gpg-agent's accepted-socket inodes.
//  2. For each, look up the peer inode (the client socket) via the peer map
//     built from all ss records.
//  3. Find the client's ss record by its local inode → read users field → PID.
//  4. Read /proc/PID/cmdline for the full command line.
func findGPGContext() string {
	agentPaths := gpgAgentSocketPaths()
	if len(agentPaths) == 0 {
		log.Debug("findGPGContext: no gpg-agent socket paths found")
		return ""
	}
	log.Debugf("findGPGContext: gpg-agent socket paths: %v", agentPaths)

	sockets, err := parseSSSockets()
	if err != nil {
		log.Debugf("findGPGContext: parseSSSockets error: %v", err)
		return ""
	}
	log.Debugf("findGPGContext: ss returned %d socket records", len(sockets))

	// Build localIno → socket record for fast lookups.
	byLocalIno := make(map[uint32]*ssSocketInfo, len(sockets))
	for i := range sockets {
		s := &sockets[i]
		byLocalIno[s.localIno] = s
	}

	// Collect gpg-agent's accepted-socket inodes: ESTAB records whose local
	// address is one of gpg-agent's socket paths.
	gpgAgentInodes := map[uint32]bool{}
	for i := range sockets {
		s := &sockets[i]
		if s.state == "ESTAB" && agentPaths[s.localAddr] {
			gpgAgentInodes[s.localIno] = true
			log.Debugf("findGPGContext: gpg-agent accepted socket: localAddr=%q localIno=%d peerIno=%d", s.localAddr, s.localIno, s.peerIno)
		}
	}
	log.Debugf("findGPGContext: gpg-agent has %d ESTAB sockets", len(gpgAgentInodes))

	var results []string
	seen := map[int32]bool{}
	for agentIno := range gpgAgentInodes {
		agentSock := byLocalIno[agentIno]
		clientIno := agentSock.peerIno
		if clientIno == 0 {
			continue
		}
		clientSock, ok := byLocalIno[clientIno]
		if !ok {
			log.Debugf("findGPGContext: client inode %d not in ss output", clientIno)
			continue
		}
		clientPID := clientSock.pid
		if clientPID == 0 {
			log.Debugf("findGPGContext: client inode %d has no pid in ss output", clientIno)
			continue
		}
		if seen[clientPID] {
			continue
		}
		seen[clientPID] = true
		if gpgContextExcluded[clientSock.procName] {
			log.Debugf("findGPGContext: pid %d (%s) excluded", clientPID, clientSock.procName)
			continue
		}
		cmdline := getProcessCmdline(clientPID)
		if cmdline == "" {
			log.Debugf("findGPGContext: pid %d has empty cmdline", clientPID)
			continue
		}
		fields := strings.Fields(cmdline)
		if gpgContextExcluded[path.Base(fields[0])] {
			log.Debugf("findGPGContext: pid %d (%s) excluded by cmdline", clientPID, fields[0])
			continue
		}
		log.Debugf("findGPGContext: caller pid=%d cmdline=%q", clientPID, cmdline)
		results = append(results, cmdline)
	}

	result := strings.Join(results, "\n")
	log.Debugf("findGPGContext: returning %q", result)
	return result
}
