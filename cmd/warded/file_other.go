// +build !linux

package main

import (
	"io/ioutil"
	"os"
)

// GetMemFile returns a file in $WARDED_TMPDIR,
// or the OS default temp directory.
// It's unlikely that this will actually reside in memory.
func GetMemFile(name string) (*os.File, error) {
	return ioutil.TempFile(os.Getenv("WARDED_TMPDIR"), name)
}
