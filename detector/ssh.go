package detector

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

// WatchSSH watches for hints that YubiKey is maybe waiting for a touch on a SSH auth request.
// The proxy is re-established whenever the agent socket disappears or gets replaced (e.g. after a suspend/resume).
func WatchSSH(requestGPGCheck chan bool, exits *sync.Map) {
	socketFile := findSSHSocket()
	if socketFile == "" {
		log.Error("Cannot watch SSH. $SSH_AUTH_SOCK is not defined, gpgconf --list-dirs agent-ssh-socket didn't help, and $XDG_RUNTIME_DIR is not defined.")
		return
	}

	exit := make(chan bool)
	exits.Store("detector/ssh", exit)
	defer exits.Delete("detector/ssh")
	lastError := ""

	for {
		session, err := installSSHProxy(socketFile)
		if err != nil {
			if message := err.Error(); message != lastError {
				log.Errorf("Cannot watch SSH: %v", err)
				lastError = message
			}
			select {
			case <-exit:
				exit <- true
				return
			case <-time.After(time.Second):
			}
			continue
		}
		lastError = ""
		log.Debug("SSH watcher is successfully established")

		acceptResult := make(chan error, 1)
		go func() {
			acceptResult <- session.accept(requestGPGCheck)
		}()
		ticker := time.NewTicker(time.Second)
		restart := false
		for !restart {
			select {
			case <-exit:
				ticker.Stop()
				session.close(true)
				exit <- true
				return
			case err := <-acceptResult:
				if !errors.Is(err, net.ErrClosed) {
					log.Errorf("SSH proxy stopped accepting connections: %v", err)
				}
				restart = true
			case <-ticker.C:
				if session.pathChanged() {
					log.Warnf("SSH socket '%v' was removed or replaced, re-establishing the watcher", socketFile)
					restart = true
				}
			}
		}
		ticker.Stop()
		session.close(false)
	}
}

func findSSHSocket() string {
	socketFile := os.Getenv("SSH_AUTH_SOCK")

	if socketFile == "" {
		gpgAgentSocket, err := exec.Command("gpgconf", "--list-dirs", "agent-ssh-socket").CombinedOutput()
		gpgAgentSocketOutput := strings.TrimSpace(string(gpgAgentSocket))
		if err != nil {
			log.Errorf("Cannot find SSH socket using gpgconf, error: %v, stderr: %v", err, gpgAgentSocketOutput)
		} else {
			socketFile = gpgAgentSocketOutput
		}
	}

	if socketFile == "" {
		runtimeDir := os.Getenv("XDG_RUNTIME_DIR")
		if runtimeDir != "" {
			socketFile = path.Join(runtimeDir, "gnupg/S.gpg-agent.ssh")
		}
	}

	return socketFile
}

func isSocketAlive(socketFile string) bool {
	conn, err := net.DialTimeout("unix", socketFile, time.Second)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

type sshProxySession struct {
	listener       *net.UnixListener
	socketFile     string
	originalSocket string
	proxyInfo      os.FileInfo
}

func installSSHProxy(socketFile string) (*sshProxySession, error) {
	if _, err := os.Stat(socketFile); err != nil {
		return nil, fmt.Errorf("the socket '%v' does not exist: %w", socketFile, err)
	}

	originalSocketFile := socketFile + ".original"
	if _, err := os.Stat(originalSocketFile); err == nil {
		switch {
		case isSocketAlive(socketFile):
			// The agent has been restarted and created a fresh socket, the backup is stale
			log.Warnf("'%v' is stale, removing it", originalSocketFile)
			if err := os.Remove(originalSocketFile); err != nil {
				return nil, fmt.Errorf("cannot remove stale '%v': %w", originalSocketFile, err)
			}
		case isSocketAlive(originalSocketFile):
			log.Warnf("'%v' already exists, assuming it's the correct one and trying to recover", originalSocketFile)
			if err := os.Remove(socketFile); err != nil {
				return nil, fmt.Errorf("cannot remove '%v' in order to recover from possible previous crash: %w", socketFile, err)
			}
		default:
			log.Warnf("Neither '%v' nor '%v' is alive, removing both", socketFile, originalSocketFile)
			os.Remove(originalSocketFile)
			os.Remove(socketFile)
			return nil, fmt.Errorf("no live SSH agent socket at '%v'", socketFile)
		}
	}

	if _, err := os.Stat(originalSocketFile); err != nil {
		if err := os.Rename(socketFile, originalSocketFile); err != nil {
			return nil, fmt.Errorf("cannot move original SSH socket file to setup a proxy: %w", err)
		}
	}

	listener, err := net.Listen("unix", socketFile)
	if err != nil {
		if renameErr := os.Rename(originalSocketFile, socketFile); renameErr != nil {
			log.Error("Cannot restore original SSH socket: ", renameErr)
		}
		return nil, fmt.Errorf("cannot establish a proxy SSH socket: %w", err)
	}
	unixListener := listener.(*net.UnixListener)
	// Never unlink by path: it may point to a socket created by a restarted agent
	unixListener.SetUnlinkOnClose(false)

	info, err := os.Stat(socketFile)
	if err != nil {
		unixListener.Close()
		return nil, fmt.Errorf("cannot stat proxy SSH socket: %w", err)
	}

	return &sshProxySession{unixListener, socketFile, originalSocketFile, info}, nil
}

func (s *sshProxySession) pathChanged() bool {
	info, err := os.Stat(s.socketFile)
	return err != nil || !os.SameFile(info, s.proxyInfo)
}

func (s *sshProxySession) close(restore bool) {
	if err := s.listener.Close(); err != nil {
		log.Error("Cannot cleanup proxy SSH socket: ", err)
	}

	if s.pathChanged() {
		// Proxy was removed or replaced: the original is only worth restoring if nothing took its place and the agent still runs
		if _, err := os.Stat(s.socketFile); err == nil {
			os.Remove(s.originalSocket)
			return
		}
		if !isSocketAlive(s.originalSocket) {
			os.Remove(s.originalSocket)
			return
		}
	}

	if err := os.Rename(s.originalSocket, s.socketFile); err != nil {
		log.Error("Cannot restore original SSH socket: ", err)
	}
}

func (s *sshProxySession) accept(requestGPGCheck chan bool) error {
	for {
		proxyConnection, err := s.listener.Accept()
		if err != nil {
			return err
		}
		originalConnection, err := net.Dial("unix", s.originalSocket)
		if err != nil {
			log.Error("Cannot establish connection to original socket: ", err)
			proxyConnection.Close()
			continue
		}

		go proxyUnixSocket(proxyConnection, originalConnection, requestGPGCheck)
		go proxyUnixSocket(originalConnection, proxyConnection, requestGPGCheck)
	}
}

func proxyUnixSocket(reader net.Conn, writer net.Conn, requestGPGCheck chan bool) {
	defer (func() {
		reader.Close()
		writer.Close()
	})()

	buf := make([]byte, 10240)
	for {
		nr, err := reader.Read(buf)
		if err != nil {
			return
		}

		data := buf[0:nr]
		if _, err = writer.Write(data); err != nil {
			return
		}

		select {
		case requestGPGCheck <- true:
		default:
		}
	}
}
