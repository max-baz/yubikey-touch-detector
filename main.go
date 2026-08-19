package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"

	log "github.com/sirupsen/logrus"

	"github.com/maximbaz/yubikey-touch-detector/notifier"
)

// Override with -ldflags "-X main.version=xxx" when compiling not from a git-archive tarball
var version = "$Format:%(describe)$"

func main() {
	truthyValues := map[string]bool{"true": true, "yes": true, "1": true}

	envVerbose := truthyValues[strings.ToLower(os.Getenv("YUBIKEY_TOUCH_DETECTOR_VERBOSE"))]
	envLibnotify := truthyValues[strings.ToLower(os.Getenv("YUBIKEY_TOUCH_DETECTOR_LIBNOTIFY"))]
	envStdout := truthyValues[strings.ToLower(os.Getenv("YUBIKEY_TOUCH_DETECTOR_STDOUT"))]
	envNosocket := truthyValues[strings.ToLower(os.Getenv("YUBIKEY_TOUCH_DETECTOR_NOSOCKET"))]
	envDbus := truthyValues[strings.ToLower(os.Getenv("YUBIKEY_TOUCH_DETECTOR_DBUS"))]

	var version bool
	var verbose bool
	var libnotify bool
	var stdout bool
	var nosocket bool
	var dbus bool

	flag.BoolVar(&version, "version", false, "print version and exit")
	flag.BoolVar(&verbose, "v", envVerbose, "enable debug logging")
	flag.BoolVar(&libnotify, "libnotify", envLibnotify, "show desktop notifications using libnotify")
	flag.BoolVar(&stdout, "stdout", envStdout, "print notifications to stdout")
	flag.BoolVar(&nosocket, "no-socket", envNosocket, "disable unix socket notifier")
	flag.BoolVar(&dbus, "dbus", envDbus, "enable dbus server for IPC")
	flag.Parse()

	if version {
		fmt.Println("YubiKey touch detector version:", appVersion())
		os.Exit(0)
	}

	if verbose {
		log.SetLevel(log.DebugLevel)
	}

	log.SetFormatter(&log.TextFormatter{FullTimestamp: true})
	log.Debug("Starting YubiKey touch detector")

	exits := &sync.Map{}
	go setupExitSignalWatch(exits)

	notifiers := &sync.Map{}

	if verbose {
		go notifier.SetupDebugNotifier(notifiers)
	}
	if !nosocket {
		go notifier.SetupUnixSocketNotifier(notifiers, exits)
	}
	if libnotify {
		go notifier.SetupLibnotifyNotifier(notifiers)
	}
	if stdout {
		go notifier.SetupStdoutNotifier(notifiers)
	}
	if dbus {
		go notifier.SetupDbusNotifier(notifiers)
	}

	initDetectors(notifiers, exits)

	wait := make(chan bool)
	<-wait
}

func setupExitSignalWatch(exits *sync.Map) {
	exitSignal := make(chan os.Signal, 1)
	signal.Notify(exitSignal, os.Interrupt, syscall.SIGTERM)

	<-exitSignal
	println()

	exits.Range(func(_, v interface{}) bool {
		exit := v.(chan bool)
		exit <- true // Notify exit watcher
		<-exit       // Wait for confirmation
		return true
	})

	log.Debug("Stopping YubiKey touch detector")
	os.Exit(0)
}

func appVersion() string {
	if strings.HasPrefix(version, "$") {
		return "unknown"
	}
	return version
}
