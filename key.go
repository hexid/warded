package warded

import "syscall"

// Key is a byte array that can be locked and unlocked
// to ensure that it isn't moved out of memory.
type Key []byte

// Lock will keep the key in memory.
func (k Key) Lock() error {
	return syscall.Mlock(k)
}

// Unlock will clear the key and allow it to move out of memory.
func (k Key) Unlock() error {
	for i := range k {
		k[i] = 0
	}
	return syscall.Munlock(k)
}
