package notifier

import "os"

func socketRuntimeDir() string {
	return os.Getenv("XDG_RUNTIME_DIR")
}
