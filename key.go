package warded

import (
	"syscall"

	"golang.org/x/crypto/scrypt"
)

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

// KeyDerivation is an interface wrapper around key derivation functions.
type KeyDerivation interface {
	NewKey(masterKey []byte, salt []byte) ([]byte, error)
}

// Scrypt holds the CPU/memory cost parameters
// used in the scrypt key derivation function
type Scrypt struct {
	Iterations int `json:"N"`
	BlockSize  int `json:"r"`
	Parallel   int `json:"p"`
}

// NewKey creates a new key from the scrypt key derivation function
func (s Scrypt) NewKey(masterKey []byte, salt []byte) ([]byte, error) {
	return scrypt.Key(masterKey, salt, s.Iterations, s.BlockSize, s.Parallel, 32)
}
