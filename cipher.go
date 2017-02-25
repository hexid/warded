package warded

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"strings"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/nacl/secretbox"
)

type cipherType int

const (
	// TypeChacha20poly1305 is the type representing the chacha20poly1305 cipher
	TypeChacha20poly1305 cipherType = iota
	// TypeXsalsa20poly1305 is the type representing the xsalsa20poly1305 cipher
	TypeXsalsa20poly1305
)

var cipherTypeHandlers = map[cipherType]func() Cipher{
	TypeChacha20poly1305: func() Cipher { return &cipherChacha20poly1305{} },
	TypeXsalsa20poly1305: func() Cipher { return &cipherXsalsa20poly1305{} },
}

// Cipher is an interface for wrapping supported ciphers
type Cipher interface {
	Seal(plaintext []byte, keyFn KeyDerivationFunc) error
	Open(keyFn KeyDerivationFunc) ([]byte, error)
}

func newCipher(cipherName string) CipherConfig {
	conf := CipherConfig{}

	switch strings.ToLower(cipherName) {
	case "xsalsa20poly1305":
		conf.Type = TypeXsalsa20poly1305
	case "chacha20poly1305":
		fallthrough
	default:
		conf.Type = TypeChacha20poly1305
	}

	conf.Data = cipherTypeHandlers[conf.Type]()
	return conf
}

// CipherConfig is the configuration for a Cipher
type CipherConfig struct {
	Type cipherType `json:"type"`
	Data Cipher     `json:"data"`
}

// UnmarshalJSON unmarshals JSON into a CipherConfig.
// This uses the Type to determine which cipher
// to marshal the data into.
func (c *CipherConfig) UnmarshalJSON(b []byte) error {
	var temp struct {
		Type cipherType
		Data *json.RawMessage
	}
	if err := json.Unmarshal(b, &temp); err != nil {
		return err
	}
	c.Type = temp.Type
	c.Data = cipherTypeHandlers[c.Type]()
	return json.Unmarshal(*temp.Data, c.Data)
}

type cipherChacha20poly1305 struct {
	Nonce      [chacha20poly1305.NonceSize]byte `json:"nonce"`
	Ciphertext []byte                           `json:"ciphertext"`
}

func (a *cipherChacha20poly1305) Seal(plaintext []byte, keyFn KeyDerivationFunc) error {
	var err error
	var key []byte
	var aead cipher.AEAD

	if key, err = keyFn(chacha20poly1305.KeySize); err != nil {
		return err
	}

	if aead, err = chacha20poly1305.New(key); err != nil {
		return err
	}

	if _, err = io.ReadFull(rand.Reader, a.Nonce[:]); err != nil {
		return err
	}

	a.Ciphertext = aead.Seal(nil, a.Nonce[:], plaintext, nil)
	return nil
}
func (a *cipherChacha20poly1305) Open(keyFn KeyDerivationFunc) ([]byte, error) {
	var key []byte
	var aead cipher.AEAD
	var err error

	if key, err = keyFn(chacha20poly1305.KeySize); err != nil {
		return nil, err
	}
	if aead, err = chacha20poly1305.New(key); err != nil {
		return nil, err
	}
	return aead.Open(nil, a.Nonce[:], a.Ciphertext, nil)
}

type cipherXsalsa20poly1305 struct {
	Nonce      [24]byte `json:"nonce"`
	Ciphertext []byte   `json:"ciphertext"`
}

func (a *cipherXsalsa20poly1305) Seal(plaintext []byte, keyFn KeyDerivationFunc) error {
	var err error
	var key []byte
	var keyArr [32]byte

	if key, err = keyFn(32); err != nil {
		return err
	}
	copy(keyArr[:], key)

	if _, err = io.ReadFull(rand.Reader, a.Nonce[:]); err != nil {
		return err
	}

	a.Ciphertext = secretbox.Seal(nil, plaintext, &a.Nonce, &keyArr)
	return nil
}

func (a *cipherXsalsa20poly1305) Open(keyFn KeyDerivationFunc) ([]byte, error) {
	var err error
	var key []byte
	var keyArr [32]byte

	if key, err = keyFn(32); err != nil {
		return nil, err
	}
	copy(keyArr[:], key)

	if dec, ok := secretbox.Open(nil, a.Ciphertext, &a.Nonce, &keyArr); ok {
		return dec, nil
	}
	return nil, errors.New("Failed to decrypt")
}
