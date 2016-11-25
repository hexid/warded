package main

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/codahale/chacha20poly1305"
	"golang.org/x/crypto/scrypt"
	"io/ioutil"
	"os"
	"path/filepath"
)

type WardedPassphrase struct {
	Nonce      []byte
	Salt       []byte
	Ciphertext []byte
}

func ReadWardedPassphrase(filename string) (WardedPassphrase, error) {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return WardedPassphrase{}, err
	}

	var pass WardedPassphrase
	json.Unmarshal(data, &pass)

	if binary.Size(pass.Nonce) == 0 || binary.Size(pass.Salt) == 0 || binary.Size(pass.Ciphertext) == 0 {
		return pass, errors.New(fmt.Sprintf("Invalid WardedPassphrase in %s", filename))
	}

	return pass, nil
}

func (pass WardedPassphrase) Write(filename string, perms os.FileMode) error {
	data, err := json.MarshalIndent(pass, "", "\t")
	if err != nil {
		return err
	}

	dir := filepath.Dir(filename)
	os.MkdirAll(dir, 0700)

	ioutil.WriteFile(filename, data, perms)
	return nil
}

func (pass *WardedPassphrase) Encrypt(masterKey []byte, plaintext []byte) error {
	// new salt on every encrypt
	pass.Salt = make([]byte, 8)
	rand.Read(pass.Salt)

	key, err := scrypt.Key(masterKey, pass.Salt, 16384, 8, 1, 32)
	if err != nil {
		return err
	}

	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return err
	}

	// new nonce on every encrypt
	pass.Nonce = make([]byte, 8)
	rand.Read(pass.Nonce)

	pass.Ciphertext = aead.Seal(nil, pass.Nonce, plaintext, nil)
	return nil
}

func (pass WardedPassphrase) Decrypt(masterKey []byte) ([]byte, error) {
	var plaintext, key []byte
	var aead cipher.AEAD
	var err error
	if key, err = scrypt.Key(masterKey, pass.Salt, 16384, 8, 1, 32); err == nil {
		if aead, err = chacha20poly1305.New(key); err == nil {
			plaintext, err = aead.Open(nil, pass.Nonce, pass.Ciphertext, nil)
		}
	}
	return plaintext, err
}
