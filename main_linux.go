package main

import (
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"

	"github.com/proglottis/gpgme"
	log "github.com/sirupsen/logrus"

	"github.com/maximbaz/yubikey-touch-detector/detector"
)

func initDetectors(notifiers, exits *sync.Map) {
	go detector.WatchU2F(notifiers)
	go detector.WatchHMAC(notifiers)
	initGPGBasedDetectors(notifiers, exits)
}

func initGPGBasedDetectors(notifiers, exits *sync.Map) {
	ctx, err := gpgme.New()
	if err != nil {
		log.Debugf("Cannot initialize GPG context: %v. Disabling GPG and SSH watchers.", err)
		return
	}

	if ctx.SetProtocol(gpgme.ProtocolAssuan) != nil {
		log.Debugf("Cannot initialize Assuan IPC: %v. Disabling GPG and SSH watchers.", err)
		return
	}

	var gpgPrivateKeysDirPath = path.Join(gpgme.GetDirInfo("homedir"), "private-keys-v1.d")
	if _, err := os.Stat(gpgPrivateKeysDirPath); err != nil {
		log.Debugf("Directory '%s' does not exist or cannot stat it\n", gpgPrivateKeysDirPath)
		return
	}

	filesToWatch, err := findShadowedPrivateKeys(gpgPrivateKeysDirPath)
	if err != nil {
		log.Debugf("Error finding shadowed private keys: %v\n", err)
		return
	}

	if len(filesToWatch) == 0 {
		log.Debugf("No shadowed private keys found.\n")
		return
	}

	requestGPGCheck := make(chan bool)
	go detector.CheckGPGOnRequest(requestGPGCheck, notifiers, ctx)
	go detector.WatchGPG(filesToWatch, requestGPGCheck)
	go detector.WatchSSH(requestGPGCheck, exits)
}

func findShadowedPrivateKeys(folderPath string) ([]string, error) {
	var result []string
	err := filepath.WalkDir(folderPath, func(path string, info os.DirEntry, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if strings.Contains(string(data), "shadowed-private-key") {
			result = append(result, path)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}
