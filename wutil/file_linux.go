// +build linux

package wutil

import (
	"io/ioutil"
	"os"
)

func GetMemFile(name string) (*os.File, error) {
	dir := os.Getenv("WARDED_TMPDIR")
	if dir == "" {
		dir = "/dev/shm"
	}
	return ioutil.TempFile("/dev/shm", name)
}
