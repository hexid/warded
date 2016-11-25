package main

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"github.com/hexid/warded/wutil"
	"golang.org/x/crypto/ssh/terminal"
	"io"
	"io/ioutil"
	"log"
	"math/big"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"syscall"
)

func EditPassphrase(wardDir string, passName string) error {
	passPath := path.Join(wardDir, passName)
	masterKey := readMasterKey()

	warded, err := ReadWardedPassphrase(passPath)

	var pass []byte
	if err != nil {
		// there is no existing file (or we can't access it)
		// we check that this key matches the rest of the ward
		// this is done by checking against a random passphrase
		checkPass := getRandPassphrase(wardDir)

		_, err = checkPass.Decrypt(masterKey)
		if err != nil {
			return errors.New("Only one master key is allowed per ward")
		}

		pass = []byte{}
	} else {
		pass, err = warded.Decrypt(masterKey)
		if err != nil {
			return errors.New("Invalid master key")
		}
	}

	plaintext := editorTemp(wardDir, pass)

	if bytes.Equal(plaintext, pass) {
		return errors.New("Passphrase unchanged")
	}

	warded.Encrypt(masterKey, plaintext)
	warded.Write(passPath, 0600)
	fmt.Println("Modified passphrase")
	return nil
}

func RekeyWard(dir string, wardName string) error {
	wardDir := path.Join(dir, wardName)
	passphrases := getPassphrases(wardDir)

	fmt.Print("Old ")
	masterKey := readMasterKey()

	fmt.Print("New ")
	newMasterKey := readMasterKey()

	fmt.Print("Confirm New ")
	if confirm := confirmMasterKey(newMasterKey); !confirm {
		return errors.New("Confirmation does not match new master key")
	}

	tmpDir, tmpErr := ioutil.TempDir(dir, wardName)
	if tmpErr != nil {
		return tmpErr
	}
	defer os.RemoveAll(tmpDir)

	for passName, warded := range passphrases {
		plaintext, decErr := warded.Decrypt(masterKey)
		if decErr != nil {
			fmt.Printf("Invalid master key for %s\n", passName)
		}
		warded.Encrypt(newMasterKey, plaintext)
		warded.Write(path.Join(tmpDir, passName), 0600)
	}

	os.RemoveAll(wardDir)
	mvErr := os.Rename(tmpDir, wardDir)
	return mvErr
}

func GetPassphrase(passPath string) []byte {
	masterKey := readMasterKey()
	warded, err := ReadWardedPassphrase(passPath)
	if err != nil {
		panic(err)
	}

	pass, decErr := warded.Decrypt(masterKey)
	if decErr != nil {
		log.Fatal(decErr)
	}
	return pass
}

func ReplacePassphrase(wardDir string, passName string, passStr string) (string, error) {
	passPath := path.Join(wardDir, passName)

	masterKey := readMasterKey()
	warded, err := ReadWardedPassphrase(passPath)

	var pass []byte
	if err != nil {
		// passName does not exist, get a random passphrase
		checkPass := getRandPassphrase(wardDir)

		// check that the provided master key can decrypt the random passphrase
		if _, err = checkPass.Decrypt(masterKey); err != nil {
			return "", errors.New("Only one master key is allowed per ward")
		}

		pass = []byte{}
	} else if pass, err = warded.Decrypt(masterKey); err != nil {
		return "", errors.New("Invalid master key")
	}

	var index int
	var value byte
	for index, value = range pass {
		if value == '\n' {
			break
		}
	}

	newPass := []byte(passStr + string(pass[index:]))
	warded.Encrypt(masterKey, newPass)
	warded.Write(passPath, 0600)

	return string(pass[:index]), nil
}

func getPassphrases(dir string) map[string]WardedPassphrase {
	passphrases := make(map[string]WardedPassphrase)
	err := filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if !info.IsDir() {
			rel, pathErr := filepath.Rel(dir, p)
			if pathErr != nil {
				return pathErr
			}

			pass, passErr := ReadWardedPassphrase(p)
			if passErr != nil {
				return passErr
			}

			passphrases[rel] = pass
		}
		return nil
	})
	if err != nil {
		panic(err)
	}

	return passphrases
}
func getRandPassphrase(dir string) WardedPassphrase {
	passphrases := getPassphrases(dir)
	plen := int64(len(passphrases))
	rind, err := rand.Int(rand.Reader, big.NewInt(plen))
	if err != nil {
		panic(err)
	}

	ind := int64(0)
	var checkPass WardedPassphrase
	for _, val := range passphrases {
		if ind == rind.Int64() {
			checkPass = val
			break
		}
		ind += 1
	}
	return checkPass
}

func readMasterKey() []byte {
	fmt.Print("Master Key: ")
	key, err := terminal.ReadPassword(syscall.Stdin)
	fmt.Println()
	if err != nil {
		panic(err)
	}
	return key
}

func confirmMasterKey(key []byte) bool {
	confirm := readMasterKey()
	return bytes.Equal(key, confirm)
}

func editorTemp(wardDir string, pass []byte) []byte {
	editor := os.Getenv("EDITOR")
	if editor == "" {
		editor = "/usr/bin/env vi"
	}

	secFile, secErr := wutil.GetMemFile("warded")
	if secErr != nil {
		panic(secErr)
	}
	defer os.Remove(secFile.Name())

	secFile.Chmod(0600)

	cmd := exec.Command(editor, secFile.Name())
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	secFile.Write(pass)
	secFile.Close()

	cmdErr := cmd.Run()
	if cmdErr != nil {
		panic(cmdErr)
	}

	readFile, _ := os.Open(secFile.Name())

	buf := new(bytes.Buffer)
	next := make([]byte, 512)
	for {
		n, err := readFile.Read(next)
		if err != nil && err != io.EOF {
			panic(err)
		}
		if n == 0 {
			break
		}
		buf.Write(next[:n])
	}

	readFile.Close()

	return buf.Bytes()
}
