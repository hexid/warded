// +build !linux

package wutil

import (
	"io/ioutil"
	"os"
)

// It's unlikely that this actually sits on memory
func GetMemFile(name string) (*os.File, error) {
	return ioutil.TempFile(os.Getenv("WARDED_TMPDIR", name)
}
