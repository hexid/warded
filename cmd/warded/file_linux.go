// +build linux

package main

import (
	"io/ioutil"
	"os"
)

// GetMemFile returns a shared memory file on Linux
func GetMemFile(name string) (*os.File, error) {
	dir := os.Getenv("WARDED_TMPDIR")
	if dir == "" {
		dir = "/dev/shm"
	}
	return ioutil.TempFile(dir, name)
}
