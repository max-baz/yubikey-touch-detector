package detector

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/proglottis/gpgme"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"

	"github.com/maximbaz/yubikey-touch-detector/notifier"
)

const gpgTouchDelay = 400 * time.Millisecond
const maxAssuanLine = 64 * 1024

type gpgOperation struct {
	blocked    map[string]bool
	generation uint64
	notified   bool
	timer      *time.Timer
}

type gpgTrackerEventKind uint8

const (
	gpgTrackerStart gpgTrackerEventKind = iota
	gpgTrackerBlock
	gpgTrackerUnblock
	gpgTrackerFinish
	gpgTrackerTimeout
	gpgTrackerReset
)

type gpgTrackerEvent struct {
	kind       gpgTrackerEventKind
	op         *gpgOperation
	reason     string
	generation uint64
}

type gpgNotificationSource uint8

const (
	gpgProxySource gpgNotificationSource = iota
	gpgBusyCheckSource
)

type gpgNotificationDelivery struct {
	output  chan notifier.Message
	updates chan notifier.Message
}

func newGPGNotificationDelivery(output chan notifier.Message) *gpgNotificationDelivery {
	delivery := &gpgNotificationDelivery{
		output:  output,
		updates: make(chan notifier.Message, 1),
	}
	go delivery.run()
	return delivery
}

func (delivery *gpgNotificationDelivery) run() {
	message := <-delivery.updates
	for {
		select {
		case delivery.output <- message:
			message = <-delivery.updates
		case message = <-delivery.updates:
		}
	}
}

func (delivery *gpgNotificationDelivery) send(message notifier.Message) {
	select {
	case delivery.updates <- message:
	default:
		select {
		case <-delivery.updates:
		default:
		}
		delivery.updates <- message
	}
}

type gpgNotifications struct {
	mutex      sync.Mutex
	active     map[gpgNotificationSource]bool
	deliveries map[chan notifier.Message]*gpgNotificationDelivery
	notifiers  *sync.Map
}

func newGPGNotifications(notifiers *sync.Map) *gpgNotifications {
	return &gpgNotifications{
		active:     make(map[gpgNotificationSource]bool),
		deliveries: make(map[chan notifier.Message]*gpgNotificationDelivery),
		notifiers:  notifiers,
	}
}

func (notifications *gpgNotifications) set(source gpgNotificationSource, active bool) {
	notifications.mutex.Lock()
	defer notifications.mutex.Unlock()
	wasActive := len(notifications.active) != 0
	if active {
		notifications.active[source] = true
	} else {
		delete(notifications.active, source)
	}
	isActive := len(notifications.active) != 0
	if wasActive == isActive {
		return
	}
	message := notifier.GPG_OFF
	if isActive {
		message = notifier.GPG_ON
	}
	notifications.notifiers.Range(func(_, value interface{}) bool {
		output := value.(chan notifier.Message)
		delivery := notifications.deliveries[output]
		if delivery == nil {
			delivery = newGPGNotificationDelivery(output)
			notifications.deliveries[output] = delivery
		}
		delivery.send(message)
		return true
	})
}

type gpgOperationTracker struct {
	delay         time.Duration
	events        chan gpgTrackerEvent
	notifications *gpgNotifications
}

func newGPGOperationTracker(notifications *gpgNotifications, delay time.Duration) *gpgOperationTracker {
	tracker := &gpgOperationTracker{
		delay:         delay,
		events:        make(chan gpgTrackerEvent, 128),
		notifications: notifications,
	}
	go tracker.run()
	return tracker
}

func (tracker *gpgOperationTracker) start() *gpgOperation {
	op := &gpgOperation{blocked: make(map[string]bool)}
	tracker.events <- gpgTrackerEvent{kind: gpgTrackerStart, op: op}
	return op
}

func (tracker *gpgOperationTracker) block(op *gpgOperation, reason string) {
	if op != nil {
		tracker.events <- gpgTrackerEvent{kind: gpgTrackerBlock, op: op, reason: reason}
	}
}

func (tracker *gpgOperationTracker) unblock(op *gpgOperation, reason string) {
	if op != nil {
		tracker.events <- gpgTrackerEvent{kind: gpgTrackerUnblock, op: op, reason: reason}
	}
}

func (tracker *gpgOperationTracker) finish(op *gpgOperation) {
	if op != nil {
		tracker.events <- gpgTrackerEvent{kind: gpgTrackerFinish, op: op}
	}
}

func (tracker *gpgOperationTracker) reset() {
	tracker.events <- gpgTrackerEvent{kind: gpgTrackerReset}
}

func (tracker *gpgOperationTracker) run() {
	var queue []*gpgOperation

	indexOf := func(op *gpgOperation) int {
		for index, candidate := range queue {
			if candidate == op {
				return index
			}
		}
		return -1
	}

	stop := func(op *gpgOperation) {
		op.generation++
		if op.timer != nil {
			op.timer.Stop()
			op.timer = nil
		}
	}

	start := func(op *gpgOperation) {
		if op == nil || len(op.blocked) != 0 || op.notified || op.timer != nil {
			return
		}
		op.generation++
		generation := op.generation
		op.timer = time.AfterFunc(tracker.delay, func() {
			tracker.events <- gpgTrackerEvent{kind: gpgTrackerTimeout, op: op, generation: generation}
		})
	}

	for event := range tracker.events {
		switch event.kind {
		case gpgTrackerStart:
			queue = append(queue, event.op)
			if len(queue) == 1 {
				start(event.op)
			}
		case gpgTrackerBlock:
			if indexOf(event.op) < 0 {
				continue
			}
			event.op.blocked[event.reason] = true
			if queue[0] == event.op {
				stop(event.op)
				if event.op.notified {
					event.op.notified = false
					tracker.notifications.set(gpgProxySource, false)
				}
			}
		case gpgTrackerUnblock:
			if indexOf(event.op) < 0 {
				continue
			}
			delete(event.op.blocked, event.reason)
			if queue[0] == event.op {
				start(event.op)
			}
		case gpgTrackerFinish:
			index := indexOf(event.op)
			if index < 0 {
				continue
			}
			wasHead := index == 0
			stop(event.op)
			if event.op.notified {
				event.op.notified = false
				tracker.notifications.set(gpgProxySource, false)
			}
			queue = append(queue[:index], queue[index+1:]...)
			if wasHead && len(queue) != 0 {
				start(queue[0])
			}
		case gpgTrackerTimeout:
			if len(queue) == 0 || queue[0] != event.op || event.op.generation != event.generation || len(event.op.blocked) != 0 || event.op.notified {
				continue
			}
			event.op.timer = nil
			event.op.notified = true
			tracker.notifications.set(gpgProxySource, true)
		case gpgTrackerReset:
			wasNotified := false
			for _, op := range queue {
				stop(op)
				wasNotified = wasNotified || op.notified
			}
			queue = nil
			if wasNotified {
				tracker.notifications.set(gpgProxySource, false)
			}
		}
	}
}

type assuanLineParser struct {
	buffer []byte
}

func (parser *assuanLineParser) feed(data []byte, callback func(line string)) {
	parser.buffer = append(parser.buffer, data...)
	for {
		index := bytes.IndexByte(parser.buffer, '\n')
		if index < 0 {
			if len(parser.buffer) > maxAssuanLine {
				parser.buffer = nil
			}
			return
		}
		line := strings.TrimSuffix(string(parser.buffer[:index]), "\r")
		parser.buffer = parser.buffer[index+1:]
		callback(line)
	}
}

type gpgAgentConnectionState struct {
	mutex      sync.Mutex
	tracker    *gpgOperationTracker
	cardKeys   map[string]bool
	signingKey string
	decryptKey string
	operation  *gpgOperation
	inquiry    bool
	closed     bool
}

func normalizeKeygrip(value string) string {
	return strings.ToUpper(strings.TrimSpace(value))
}

func (state *gpgAgentConnectionState) isCardKey(keygrip string) bool {
	return state.cardKeys[normalizeKeygrip(keygrip)]
}

func (state *gpgAgentConnectionState) startOperation(cardBacked bool) {
	if state.operation != nil {
		state.tracker.finish(state.operation)
		state.operation = nil
	}
	state.inquiry = false
	if cardBacked {
		state.operation = state.tracker.start()
	}
}

func (state *gpgAgentConnectionState) handleClientLine(line string) {
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return
	}

	state.mutex.Lock()
	defer state.mutex.Unlock()
	if state.closed {
		return
	}

	switch fields[0] {
	case "SIGKEY":
		if len(fields) > 1 {
			state.signingKey = normalizeKeygrip(fields[len(fields)-1])
		}
	case "SETKEY":
		if len(fields) > 1 {
			state.decryptKey = normalizeKeygrip(fields[len(fields)-1])
		}
	case "PKSIGN":
		state.startOperation(state.isCardKey(state.signingKey))
	case "PKDECRYPT":
		state.startOperation(state.isCardKey(state.decryptKey))
	case "RESET":
		state.signingKey = ""
		state.decryptKey = ""
	case "END", "CAN":
		if state.inquiry {
			state.inquiry = false
			state.tracker.unblock(state.operation, "inquiry")
		}
	}
}

func (state *gpgAgentConnectionState) blockForPinentry(pidText string) {
	pidText = strings.SplitN(pidText, ":", 2)[0]
	pid, err := strconv.Atoi(pidText)
	if err != nil || pid <= 0 {
		return
	}
	reason := fmt.Sprintf("pinentry:%d", pid)
	op := state.operation
	state.tracker.block(op, reason)
	go waitForProcess(pid, func() {
		state.tracker.unblock(op, reason)
	})
}

func (state *gpgAgentConnectionState) handleServerLine(line string) {
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return
	}

	state.mutex.Lock()
	defer state.mutex.Unlock()
	if state.closed {
		return
	}

	switch fields[0] {
	case "INQUIRE":
		if state.operation == nil {
			return
		}
		state.inquiry = true
		state.tracker.block(state.operation, "inquiry")
		if len(fields) >= 3 && fields[1] == "PINENTRY_LAUNCHED" {
			state.blockForPinentry(fields[2])
		}
	case "S":
		if state.operation == nil || len(fields) < 3 || fields[1] != "PINENTRY_LAUNCHED" {
			return
		}
		state.blockForPinentry(fields[2])
	case "OK", "ERR":
		if state.operation != nil {
			state.tracker.finish(state.operation)
			state.operation = nil
			state.inquiry = false
		}
	}
}

func (state *gpgAgentConnectionState) close() {
	state.mutex.Lock()
	defer state.mutex.Unlock()
	if state.closed {
		return
	}
	state.closed = true
	state.tracker.finish(state.operation)
	state.operation = nil
}

func waitForProcess(pid int, done func()) {
	fd, err := unix.PidfdOpen(pid, 0)
	if err == nil {
		poll := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
		for {
			_, err = unix.Poll(poll, -1)
			if err != unix.EINTR {
				break
			}
		}
		unix.Close(fd)
		if err == nil {
			done()
			return
		}
	}

	for {
		err = unix.Kill(pid, 0)
		if errors.Is(err, unix.ESRCH) {
			done()
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
}

type gpgProxySession struct {
	listener    *net.UnixListener
	publicPath  string
	backendPath string
	publicInfo  os.FileInfo
	connections sync.Map
	failure     chan struct{}
	failOnce    sync.Once
	tracker     *gpgOperationTracker
	cardKeys    map[string]bool
}

func socketAcceptsConnections(path string) bool {
	connection, err := net.DialTimeout("unix", path, 200*time.Millisecond)
	if err != nil {
		return false
	}
	connection.Close()
	return true
}

func installGPGProxy(publicPath string, tracker *gpgOperationTracker, cardKeys map[string]bool) (*gpgProxySession, error) {
	backendPath := publicPath + ".yubikey-touch-detector"
	_, publicErr := os.Lstat(publicPath)
	_, backendErr := os.Lstat(backendPath)
	publicExists := publicErr == nil
	backendExists := backendErr == nil
	publicLive := publicExists && socketAcceptsConnections(publicPath)
	backendLive := backendExists && socketAcceptsConnections(backendPath)

	if backendLive {
		if publicLive {
			return nil, fmt.Errorf("both proxy and backend sockets are active")
		}
		if publicExists {
			if err := os.Remove(publicPath); err != nil {
				return nil, err
			}
		}
	} else {
		if !publicLive {
			if publicExists {
				_ = os.Remove(publicPath)
			}
			if backendExists {
				_ = os.Remove(backendPath)
			}
			return nil, os.ErrNotExist
		}
		if err := os.Rename(publicPath, backendPath); err != nil {
			return nil, err
		}
	}

	address, err := net.ResolveUnixAddr("unix", publicPath)
	if err != nil {
		return nil, err
	}
	listener, err := net.ListenUnix("unix", address)
	if err != nil {
		_ = os.Rename(backendPath, publicPath)
		return nil, err
	}
	listener.SetUnlinkOnClose(false)
	if err := os.Chmod(publicPath, 0o600); err != nil {
		listener.Close()
		_ = os.Rename(backendPath, publicPath)
		return nil, err
	}
	publicInfo, err := os.Lstat(publicPath)
	if err != nil {
		listener.Close()
		_ = os.Rename(backendPath, publicPath)
		return nil, err
	}

	return &gpgProxySession{
		listener:    listener,
		publicPath:  publicPath,
		backendPath: backendPath,
		publicInfo:  publicInfo,
		failure:     make(chan struct{}),
		tracker:     tracker,
		cardKeys:    cardKeys,
	}, nil
}

func (session *gpgProxySession) pathChanged() bool {
	info, err := os.Lstat(session.publicPath)
	return err != nil || !os.SameFile(info, session.publicInfo)
}

func (session *gpgProxySession) fail() {
	session.failOnce.Do(func() {
		close(session.failure)
	})
}

func (session *gpgProxySession) closeConnections() {
	session.connections.Range(func(connection, _ interface{}) bool {
		connection.(*net.UnixConn).Close()
		return true
	})
}

func (session *gpgProxySession) close(restore bool) {
	ownsPublicPath := !session.pathChanged()
	session.listener.Close()
	session.closeConnections()
	session.tracker.reset()
	if !restore {
		return
	}
	if !ownsPublicPath {
		log.Warn("Cannot restore original GPG agent socket because the public socket was replaced")
		return
	}
	if err := os.Rename(session.backendPath, session.publicPath); err != nil {
		log.Errorf("Cannot restore original GPG agent socket: %v", err)
	}
}

func peerIsCurrentUser(connection *net.UnixConn) bool {
	raw, err := connection.SyscallConn()
	if err != nil {
		return false
	}
	allowed := false
	controlErr := raw.Control(func(fd uintptr) {
		credentials, err := unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
		allowed = err == nil && credentials.Uid == uint32(os.Getuid())
	})
	return controlErr == nil && allowed
}

func closeReceivedRights(oob []byte) {
	messages, err := unix.ParseSocketControlMessage(oob)
	if err != nil {
		return
	}
	for _, message := range messages {
		rights, err := unix.ParseUnixRights(&message)
		if err != nil {
			continue
		}
		for _, fd := range rights {
			_ = unix.Close(fd)
		}
	}
}

func writeUnixMessage(destination *net.UnixConn, data, oob []byte) error {
	written, oobWritten, err := destination.WriteMsgUnix(data, oob, nil)
	if err != nil {
		return err
	}
	if oobWritten != len(oob) {
		return io.ErrShortWrite
	}
	for written < len(data) {
		count, err := destination.Write(data[written:])
		if err != nil {
			return err
		}
		if count == 0 {
			return io.ErrShortWrite
		}
		written += count
	}
	return nil
}

func relayGPGAgent(source, destination *net.UnixConn, parser *assuanLineParser, handle func(string)) error {
	data := make([]byte, 32*1024)
	oob := make([]byte, 4*1024)
	for {
		dataLength, oobLength, flags, _, err := source.ReadMsgUnix(data, oob)
		if flags&unix.MSG_CTRUNC != 0 {
			if oobLength > 0 {
				closeReceivedRights(oob[:oobLength])
			}
			return fmt.Errorf("truncated Unix control message")
		}
		if dataLength > 0 {
			parser.feed(data[:dataLength], handle)
		}
		if dataLength > 0 || oobLength > 0 {
			writeErr := writeUnixMessage(destination, data[:dataLength], oob[:oobLength])
			if oobLength > 0 {
				closeReceivedRights(oob[:oobLength])
			}
			if writeErr != nil {
				return writeErr
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
	}
}

func (session *gpgProxySession) handleConnection(client *net.UnixConn) {
	if !peerIsCurrentUser(client) {
		client.Close()
		return
	}
	backendAddress, err := net.ResolveUnixAddr("unix", session.backendPath)
	if err != nil {
		client.Close()
		return
	}
	backend, err := net.DialUnix("unix", nil, backendAddress)
	if err != nil {
		session.fail()
		client.Close()
		return
	}

	session.connections.Store(client, true)
	session.connections.Store(backend, true)
	defer session.connections.Delete(client)
	defer session.connections.Delete(backend)
	defer client.Close()
	defer backend.Close()

	state := &gpgAgentConnectionState{tracker: session.tracker, cardKeys: session.cardKeys}
	defer state.close()
	clientParser := &assuanLineParser{}
	serverParser := &assuanLineParser{}
	results := make(chan error, 2)
	go func() {
		results <- relayGPGAgent(client, backend, clientParser, state.handleClientLine)
	}()
	go func() {
		results <- relayGPGAgent(backend, client, serverParser, state.handleServerLine)
	}()
	<-results
	client.Close()
	backend.Close()
	<-results
}

func (session *gpgProxySession) accept() error {
	for {
		connection, err := session.listener.AcceptUnix()
		if err != nil {
			return err
		}
		go session.handleConnection(connection)
	}
}

func findGPGAgentSocket() (string, error) {
	output, err := exec.Command("gpgconf", "--list-dirs", "agent-socket").CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("gpgconf --list-dirs agent-socket: %w: %s", err, strings.TrimSpace(string(output)))
	}
	value := strings.TrimSpace(string(output))
	if value == "" {
		return "", fmt.Errorf("gpgconf returned an empty agent socket path")
	}
	return value, nil
}

func shadowedKeygrips(files []string) map[string]bool {
	result := make(map[string]bool, len(files))
	for _, file := range files {
		name := filepath.Base(file)
		keygrip := strings.TrimSuffix(name, filepath.Ext(name))
		if keygrip != "" {
			result[normalizeKeygrip(keygrip)] = true
		}
	}
	return result
}

func watchGPGAgent(files []string, notifications *gpgNotifications, exits *sync.Map) {
	publicPath, err := findGPGAgentSocket()
	if err != nil {
		log.Errorf("Cannot find GPG agent socket: %v", err)
		return
	}
	tracker := newGPGOperationTracker(notifications, gpgTouchDelay)
	cardKeys := shadowedKeygrips(files)
	exit := make(chan bool)
	exits.Store("detector/gpg-agent", exit)
	defer exits.Delete("detector/gpg-agent")
	lastError := ""

	for {
		session, err := installGPGProxy(publicPath, tracker, cardKeys)
		if errors.Is(err, os.ErrNotExist) {
			if launchErr := exec.Command("gpgconf", "--launch", "gpg-agent").Run(); launchErr == nil {
				session, err = installGPGProxy(publicPath, tracker, cardKeys)
			}
		}
		if err != nil {
			if message := err.Error(); message != lastError {
				log.Errorf("Cannot establish GPG agent proxy: %v", err)
				lastError = message
			}
			select {
			case <-exit:
				tracker.reset()
				exit <- true
				return
			case <-time.After(time.Second):
			}
			continue
		}
		lastError = ""
		log.Debugf("GPG agent watcher is proxying '%s'", publicPath)
		acceptResult := make(chan error, 1)
		go func() {
			acceptResult <- session.accept()
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
					log.Errorf("GPG agent proxy stopped accepting connections: %v", err)
				}
				restart = true
			case <-session.failure:
				restart = true
			case <-ticker.C:
				if session.pathChanged() {
					restart = true
				}
			}
		}
		ticker.Stop()
		session.close(false)
	}
}

func checkGPGOnRequest(requestGPGCheck chan bool, notifications *gpgNotifications, ctx *gpgme.Context) {
	check := func(response chan error, timer *time.Timer) {
		err := ctx.AssuanSend("LEARN", nil, nil, func(status, args string) error {
			log.Debugf("AssuanSend/status: %v, %v", status, args)
			return nil
		})
		if !timer.Stop() {
			response <- err
		}
	}
	for range requestGPGCheck {
		response := make(chan error)
		timer := time.AfterFunc(gpgTouchDelay, func() {
			notifications.set(gpgBusyCheckSource, true)
			err := <-response
			if err != nil {
				log.Errorf("Agent returned an error: %v", err)
			}
			notifications.set(gpgBusyCheckSource, false)
		})
		time.Sleep(200 * time.Millisecond)
		check(response, timer)
	}
}

func WatchGPG(files []string, notifiers, exits *sync.Map) {
	notifications := newGPGNotifications(notifiers)
	go watchGPGAgent(files, notifications, exits)

	ctx, err := gpgme.New()
	if err != nil {
		log.Debugf("Cannot initialize GPG context: %v. Disabling SSH watcher.", err)
		return
	}
	if err := ctx.SetProtocol(gpgme.ProtocolAssuan); err != nil {
		log.Debugf("Cannot initialize Assuan IPC: %v. Disabling SSH watcher.", err)
		return
	}

	requestGPGCheck := make(chan bool)
	go checkGPGOnRequest(requestGPGCheck, notifications, ctx)
	WatchSSH(requestGPGCheck, exits)
}
