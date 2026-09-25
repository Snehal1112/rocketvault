package smoketest

import "os"

func ReadConfig(path string) *os.File {
	f, _ := os.Open(path)
	return f
}
