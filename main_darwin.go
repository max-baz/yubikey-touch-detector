package main

import (
	"sync"

	"github.com/maximbaz/yubikey-touch-detector/detector"
)

func initDetectors(notifiers, _ *sync.Map) {
	go detector.WatchMacOS(notifiers)
}
