package notifier

import "os"

func socketRuntimeDir() string {
	return os.TempDir()
}
