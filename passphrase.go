package warded

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/codahale/chacha20poly1305"
)

// Passphrase is the encrypted passphrase
type Passphrase struct {
	Nonce      []byte `json:"nonce"`
	Salt       []byte `json:"salt"`
	Ciphertext []byte `json:"ciphertext"`
	Filename   string `json:"-"`
	Scrypt     Scrypt `json:"scrypt"`
}

func defaultPassphrase(config WardConfig) *Passphrase {
	return &Passphrase{
		Scrypt: config.Scrypt,
	}
}

// NewPassphrase creates a new encrypted passphrase.
// A new passphrase should be generated every time the plaintext is changed
func (w Ward) NewPassphrase(plaintext []byte) (*Passphrase, error) {
	var err error
	var key []byte
	var aead cipher.AEAD
	pass := defaultPassphrase(w.Config)

	// new salt on every encrypt
	pass.Salt = make([]byte, 8)
	if _, err = rand.Read(pass.Salt); err != nil {
		return nil, err
	}

	if key, err = pass.Scrypt.NewKey(w.key, pass.Salt); err != nil {
		return nil, err
	}

	if aead, err = chacha20poly1305.New(key); err != nil {
		return nil, err
	}

	// new nonce on every encrypt
	pass.Nonce = make([]byte, 8)
	if _, err = rand.Read(pass.Nonce); err != nil {
		return nil, err
	}

	pass.Ciphertext = aead.Seal(nil, pass.Nonce, plaintext, nil)
	return pass, nil
}

// ReadPassphrase reads the given file and returns a Passphrase
// assuming it contains the necessary data
func ReadPassphrase(fileName string) (*Passphrase, error) {
	data, err := ioutil.ReadFile(fileName)
	if err != nil {
		return nil, err
	}

	pass := defaultPassphrase(DefaultWardConfig())
	json.Unmarshal(data, pass)
	pass.Filename = fileName

	if binary.Size(pass.Nonce) == 0 || binary.Size(pass.Salt) == 0 || binary.Size(pass.Ciphertext) == 0 {
		return nil, fmt.Errorf("Invalid Passphrase in %s", fileName)
	}

	return pass, nil
}

// Decrypt returns the plaintext passphrase, assuming
// that the correct master key has been provided.
func (pass Passphrase) Decrypt(masterKey []byte) ([]byte, error) {
	var plaintext, key []byte
	var aead cipher.AEAD
	var err error
	if key, err = pass.Scrypt.NewKey(masterKey, pass.Salt); err == nil {
		if aead, err = chacha20poly1305.New(key); err == nil {
			plaintext, err = aead.Open(nil, pass.Nonce, pass.Ciphertext, nil)
		}
	}
	return plaintext, err
}

// Write writes the Passphrase to a given file with the provided permissions
func (pass Passphrase) Write(perms os.FileMode) error {
	data, err := json.Marshal(pass)
	if err != nil {
		return err
	}

	dir := filepath.Dir(pass.Filename)
	if err = os.MkdirAll(dir, 0700); err != nil {
		return err
	}

	return ioutil.WriteFile(pass.Filename, data, perms)
}
