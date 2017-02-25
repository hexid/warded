package warded

import (
	"crypto/rand"
	"encoding/json"
	"io"

	"golang.org/x/crypto/scrypt"
)

type keyDerivationType int

const (
	// TypeScrypt is the type representing the scrypt key derivation function
	TypeScrypt keyDerivationType = iota
)

var keyDerivationTypeHandlers = map[keyDerivationType]func() KeyDerivation{
	TypeScrypt: func() KeyDerivation {
		return &Scrypt{
			Iterations: 16384,
			BlockSize:  8,
			Parallel:   1,
		}
	},
}

// KeyDerivation is an interface wrapper around key derivation functions.
type KeyDerivation interface {
	// newKeyFn creates a new key from the key derivation function
	newKeyFn(masterKey []byte) KeyDerivationFunc
	// newSalt() updates the salt used for th key derivation function.
	// This should be called before calling newKeyFn, except when
	// being used to decrypt an existing passphrase.
	newSalt() error
}

// KeyDerivationConfig is the configuration for a KeyDerivation
type KeyDerivationConfig struct {
	Type keyDerivationType `json:"type"`
	Data KeyDerivation     `json:"data"`
}

// UnmarshalJSON unmarshals JSON into a CipherConfig.
// This uses the Type to determine which key derivation
// function to marshal the data into.
func (c *KeyDerivationConfig) UnmarshalJSON(b []byte) error {
	var temp struct {
		Type keyDerivationType
		Data *json.RawMessage
	}
	if err := json.Unmarshal(b, &temp); err != nil {
		return err
	}
	c.Type = temp.Type
	c.Data = keyDerivationTypeHandlers[c.Type]()
	return json.Unmarshal(*temp.Data, &c.Data)
}

// KeyDerivationFunc is a function type that will return a key
// of the given length. This should only be called once.
type KeyDerivationFunc func(keyLen int) ([]byte, error)

func newSalt(length int) ([]byte, error) {
	salt := make([]byte, length)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}
	return salt, nil
}

// Scrypt holds the CPU/memory cost parameters
// used in the scrypt key derivation function
type Scrypt struct {
	Iterations int    `json:"N"`
	BlockSize  int    `json:"r"`
	Parallel   int    `json:"p"`
	Salt       []byte `json:"salt"`
}

func (s *Scrypt) newKeyFn(masterKey []byte) KeyDerivationFunc {
	return func(keyLen int) ([]byte, error) {
		return scrypt.Key(masterKey, s.Salt, s.Iterations, s.BlockSize, s.Parallel, keyLen)
	}
}
func (s *Scrypt) newSalt() (err error) {
	s.Salt, err = newSalt(8)
	return
}
