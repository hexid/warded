package warded

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"io/ioutil"
	"math/big"
	"os"
	"path"
	"path/filepath"
	"regexp"
)

// Ward holds data needed to work with a ward.
type Ward struct {
	Config WardConfig
	Dir    string
	key    []byte
}

// NewWard creates a Ward.
func NewWard(masterKey []byte) Ward {
	return Ward{
		Config: DefaultWardConfig(),
		key:    masterKey,
	}
}

// SearchResult contains information about a matched search
type SearchResult struct {
	Passphrase string
	Line       []byte
	LineNum    int
	IndexStart int
	IndexEnd   int
}

// Statistics holds statistics about the entire ward
type Statistics struct {
	Groups    []Group `json:"groups"`
	Count     int     `json:"count"`
	SumLength int     `json:"sum"`
	MaxLength int     `json:"max"`
}

// A Group holds the names and some statistics about a group of common passphrases
type Group struct {
	Length      int      `json:"len"`
	Passphrases []string `json:"pass"`
}

// Edit sets the entire content of the warded passphrase.
func (w Ward) Edit(passName string, content []byte) (err error) {
	var pass *Passphrase
	if pass, err = w.newPassphrase(content); err == nil {
		pass.Filename = w.Path(passName)
		err = pass.Write(0600)
	}
	return
}

// Get returns the decrypted passphrase content.
func (w Ward) Get(passName string) ([]byte, error) {
	warded, err := ReadPassphrase(w.Path(passName))
	if err != nil {
		return nil, err
	}
	return warded.Decrypt(w.key)
}

// GetOrCheck returns the decrypted passphrase content.
// If Get throws an error, the Ward's key is checked
// against a random passphrase in the Ward.
func (w Ward) GetOrCheck(passName string) ([]byte, error) {
	pass, err := w.Get(passName)
	if err != nil {
		err = w.checkKey()
	}
	return pass, err
}

// List returns a list of passphrase names in the ward
func (w Ward) List() ([]string, error) {
	passphrases := make([]string, 0)
	err := filepath.Walk(w.Dir, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		var rel string

		if !info.IsDir() {
			if rel, err = filepath.Rel(w.Dir, p); err != nil {
				return err
			}

			passphrases = append(passphrases, rel)
		}

		return nil
	})
	return passphrases, err
}

// Map returns a map of passphrase names to the warded passphrase.
func (w Ward) Map(path string) (map[string]*Passphrase, error) {
	passphrases := make(map[string]*Passphrase)
	err := filepath.Walk(w.Path(path), func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		var rel string
		var pass *Passphrase

		if !info.IsDir() {
			if rel, err = filepath.Rel(w.Dir, p); err != nil {
				return err
			}

			if pass, err = ReadPassphrase(w.Path(rel)); err != nil {
				return err
			}

			passphrases[rel] = pass
		}
		return nil
	})

	return passphrases, err
}

// Path returns the path to a passphrase.
// Generated by joining the ward directory with the cleaned passphrase name
func (w Ward) Path(passName string) string {
	return path.Join(w.Dir, path.Clean(passName))
}

// Rekey changes the master key for the entire ward.
// Any errors will cancel the operation, leaving the ward with the existing key.
func (w Ward) Rekey(newMasterKey []byte, tempDir string) error {
	passphrases, err := w.Map("")
	if err != nil {
		return err
	}

	tmpDir, err := ioutil.TempDir(tempDir, "rekey")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmpDir)

	newWard := NewWard(newMasterKey)
	newWard.Config = w.Config
	newWard.Dir = tmpDir

	var plaintext []byte
	for passName, warded := range passphrases {
		if plaintext, err = warded.Decrypt(w.key); err != nil {
			return fmt.Errorf("Invalid master key for %s\n", passName)
		}

		if err = newWard.Edit(passName, plaintext); err != nil {
			return err
		}
	}

	if err = os.RemoveAll(w.Dir); err == nil {
		err = os.Rename(tmpDir, w.Dir)
	}
	return err
}

// Search searches through a ward, printing lines
// that match the given regular expression.
func (w Ward) Search(path string, regex *regexp.Regexp) ([]SearchResult, error) {
	var err error
	var passphrases map[string]*Passphrase
	if passphrases, err = w.Map(path); err != nil {
		return nil, err
	}

	var pass []byte
	var results []SearchResult
	for passName, warded := range passphrases {
		if pass, err = warded.Decrypt(w.key); err != nil {
			return nil, err
		}

		for lineNum, line := range bytes.Split(pass, []byte("\n")) {
			for _, match := range regex.FindAllIndex(line, -1) {
				results = append(results, SearchResult{
					Passphrase: passName,
					Line:       line,
					LineNum:    lineNum,
					IndexStart: match[0],
					IndexEnd:   match[1],
				})
			}
		}
	}

	return results, nil
}

// Stats returns statistics for the current ward.
func (w Ward) Stats(path string) (*Statistics, error) {
	passphrases, err := w.Map(path)
	if err != nil {
		return nil, err
	}

	groupMap := make(map[string][]string)
	sumLen := 0
	maxLen := 0

	for name, pass := range passphrases {
		plaintext, err := pass.Decrypt(w.key)
		if err != nil {
			return nil, err
		}
		lines := bytes.SplitN(plaintext, []byte("\n"), 2)
		first := string(lines[0])
		passLen := len(first)

		groupMap[first] = append(groupMap[first], name)

		if passLen > maxLen {
			maxLen = passLen
		}
		sumLen += passLen
	}

	groups := make([]Group, len(groupMap))
	ind := 0
	for key, val := range groupMap {
		groups[ind] = Group{
			Passphrases: val,
			Length:      len(key),
		}
		ind++
	}

	return &Statistics{
		Groups:    groups,
		Count:     len(passphrases),
		MaxLength: maxLen,
		SumLength: sumLen,
	}, nil
}

// Update replaces the first line of a passphrase with the given string.
func (w Ward) Update(passName string, passStr []byte) (string, error) {
	pass, err := w.GetOrCheck(passName)
	if err != nil {
		return "", err
	}

	split := bytes.SplitN(pass, []byte("\n"), 2)
	if len(split) < 2 {
		// there was no existing passphrase, so we need to pretend there was
		split = make([][]byte, 2)
	}

	newPass := append(passStr, '\n')
	newPass = append(newPass, split[1]...)
	if err = w.Edit(passName, newPass); err != nil {
		return "", err
	}

	return string(split[0]), nil
}

func (w Ward) checkKey() (err error) {
	var passphrases []string
	if passphrases, err = w.List(); err != nil {
		return
	}

	plen := int64(len(passphrases))
	if plen == 0 {
		// there were no existing passphrases in the ward
		// this isn't considered an error
		return
	}

	var rind *big.Int
	if rind, err = rand.Int(rand.Reader, big.NewInt(plen)); err != nil {
		return
	}

	var pass *Passphrase
	if pass, err = ReadPassphrase(w.Path(passphrases[rind.Int64()])); err != nil {
		return
	}

	// check that the provided master key can decrypt the random passphrase
	if _, err = pass.Decrypt(w.key); err != nil {
		err = errors.New("Only one master key is allowed per ward")
	}

	return
}
