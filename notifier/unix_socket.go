package notifier

import (
	"net"
	"os"
	"path"
	"strings"
	"sync"

	"github.com/coreos/go-systemd/v22/activation"
	log "github.com/sirupsen/logrus"
)

// SetupUnixSocketNotifier configures a unix socket to transmit touch requests to other apps
func SetupUnixSocketNotifier(notifiers *sync.Map, exits *sync.Map) {
	socketDir := socketRuntimeDir()
	if socketDir == "" {
		log.Error("Cannot setup unix socket notifier, $XDG_RUNTIME_DIR is not defined.")
		return
	}

	if _, err := os.Stat(socketDir); err != nil {
		log.Errorf("Cannot setup unix socket notifier, folder '%v' does not exist: %v", socketDir, err)
		return
	}

	listeners, err := activation.Listeners()
	if err != nil {
		log.Errorf("Error receiving activation listeners from systemd, proceeding to create our own unix socket: %v", err)
	}

	var socket net.Listener
	if len(listeners) > 1 {
		log.Warn("Received more than one listener from systemd which should not be possible, using the first one")
		socket = listeners[0]
	} else if len(listeners) == 1 {
		socket = listeners[0]
	} else {
		socketFile := path.Join(socketDir, "yubikey-touch-detector.socket")

		if _, err := os.Stat(socketFile); err == nil {
			log.Warnf("'%v' already exists, assuming it's obsolete and trying to recover", socketFile)
			if err = os.Remove(socketFile); err != nil {
				log.Errorf("Cannot remove '%v' in order to recover from possible previous crash", socketFile)
				return
			}
		}

		socket, err = net.Listen("unix", socketFile)
		if err != nil {
			log.Error("Cannot establish a unix socket listener: ", err)
			return
		}
	}

	exit := make(chan bool)
	exits.Store("notifier/unix_socket", exit)
	go func() {
		<-exit
		if err := socket.Close(); err != nil {
			log.Error("Cannot cleanup unix socket notifier: ", err)
		}
		exit <- true
	}()

	touch := make(chan Message, 10)
	notifiers.Store("notifier/unix_socket", touch)

	touchListeners := make(map[*net.Conn]chan []byte)
	touchListenersMutex := sync.RWMutex{}
	go func() {
		for {
			value := <-touch
			touchListenersMutex.RLock()
			for _, listener := range touchListeners {
				listener <- []byte(value)
			}
			touchListenersMutex.RUnlock()
		}
	}()

	for {
		listener, err := socket.Accept()
		if err != nil {
			if !strings.Contains(err.Error(), "use of closed network connection") {
				log.Error("Cannot accept incoming unix socket notifier connection: ", err)
			}
			return
		}

		go unixSocketNotify(listener, touchListeners, &touchListenersMutex)
	}
}

func unixSocketNotify(listener net.Conn, touchListeners map[*net.Conn]chan []byte, touchListenersMutex *sync.RWMutex) {
	values := make(chan []byte)
	touchListenersMutex.Lock()
	touchListeners[&listener] = values
	touchListenersMutex.Unlock()
	defer (func() {
		touchListenersMutex.Lock()
		delete(touchListeners, &listener)
		touchListenersMutex.Unlock()
		listener.Close()
	})()

	for {
		value := <-values
		if _, err := listener.Write(value); err != nil {
			return
		}
	}
}
