package main

import (
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

func (pass WardedPassphrase) Write(filename string, perms os.FileMode) {
	data, err := json.MarshalIndent(pass, "", "\t")
	if err != nil {
		panic(err)
	}

	dir := filepath.Dir(filename)
	os.MkdirAll(dir, 0700)

	ioutil.WriteFile(filename, data, perms)
}

func (pass *WardedPassphrase) Encrypt(masterKey []byte, plaintext []byte) {
	// new salt on every encrypt
	pass.Salt = make([]byte, 8)
	rand.Read(pass.Salt)

	key, derivErr := scrypt.Key(masterKey, pass.Salt, 16384, 8, 1, 32)
	if derivErr != nil {
		panic(derivErr)
	}

	aead, hashErr := chacha20poly1305.New(key)
	if hashErr != nil {
		panic(hashErr)
	}

	// new nonce on every encrypt
	pass.Nonce = make([]byte, 8)
	rand.Read(pass.Nonce)

	pass.Ciphertext = aead.Seal(nil, pass.Nonce, plaintext, nil)
}

func (pass WardedPassphrase) Decrypt(masterKey []byte) ([]byte, error) {
	key, derivErr := scrypt.Key(masterKey, pass.Salt, 16384, 8, 1, 32)
	if derivErr != nil {
		panic(derivErr)
	}

	aead, hashErr := chacha20poly1305.New(key)
	if hashErr != nil {
		panic(hashErr)
	}

	plaintext, err := aead.Open(nil, pass.Nonce, pass.Ciphertext, nil)
	return plaintext, err
}
