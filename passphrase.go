package warded

import (
	"encoding/json"
	"io/ioutil"
	"os"
	"path/filepath"
)

// Passphrase is the encrypted passphrase
type Passphrase struct {
	Cipher        CipherConfig        `json:"cipher"`
	KeyDerivation KeyDerivationConfig `json:"keyDerivation"`
	Filename      string              `json:"-"`
}

func defaultPassphrase(config WardConfig) *Passphrase {
	return &Passphrase{
		Cipher:        newCipher(config.Cipher),
		KeyDerivation: config.KeyDerivation,
	}
}

// NewPassphrase creates a new encrypted passphrase.
// A new passphrase should be generated every time the plaintext is changed
func (w Ward) newPassphrase(plaintext []byte) (*Passphrase, error) {
	var err error
	pass := defaultPassphrase(w.Config)

	// new salt on every encrypt
	if err = pass.KeyDerivation.Data.newSalt(); err != nil {
		return nil, err
	}

	keyFn := pass.KeyDerivation.Data.newKeyFn(w.key)
	if err = pass.Cipher.Data.Seal(plaintext, keyFn); err != nil {
		return nil, err
	}

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

	return pass, nil
}

// Decrypt returns the plaintext passphrase, assuming
// that the correct master key has been provided.
func (pass Passphrase) Decrypt(masterKey []byte) ([]byte, error) {
	keyFn := pass.KeyDerivation.Data.newKeyFn(masterKey)
	return pass.Cipher.Data.Open(keyFn)
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
