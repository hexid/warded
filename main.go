package main

import (
	"bytes"
	"flag"
	"fmt"
	"github.com/cep21/xdgbasedir"
	"github.com/hexid/warded/wutil"
	"os"
	"path"
	"strconv"
	"syscall"
)

func main() {
	memErr := syscall.Mlockall(syscall.MCL_CURRENT | syscall.MCL_FUTURE)
	if memErr != nil {
		panic(memErr)
	}

	dataDir, err := xdgbasedir.DataHomeDirectory()
	if err != nil {
		panic(err)
	}
	wardedDataDir := path.Join(dataDir, "warded")

	wardName := flag.String("w", "default", "ward group name")
	flag.Parse()

	wardDir := path.Join(wardedDataDir, *wardName)

	os.MkdirAll(wardDir, 0700)

	cmd := flag.Arg(0)
	switch cmd {
	case "", "show":
		passName := flag.Arg(1)
		pass := GetPassphrase(path.Join(wardDir, passName))
		fmt.Println(string(pass[:]))
	case "edit":
		passName := flag.Arg(1)
		EditPassphrase(wardDir, passName)
	case "generate":
		passName := flag.Arg(1)
		randSize, pErr := strconv.ParseUint(flag.Arg(2), 10, 32)
		if pErr != nil {
			panic(pErr)
		}

		randType := wutil.RandAlpha | wutil.RandNum
		oldPass, newPass := GeneratePassphrase(wardDir, passName, randSize, randType)
		fmt.Printf("Old: %s\nNew: %s\n", oldPass, newPass)
	case "ls", "list":
		passphrases := getPassphrases(wardDir)
		for passName, _ := range passphrases {
			fmt.Println(passName)
		}
	case "rekey":
		RekeyWard(wardedDataDir, *wardName)
	default:
		fmt.Printf("Unknown command: %s\n", cmd)
	}
}

func setupDirectory(dataDir string) {
	os.MkdirAll(dataDir, 0700)
}

func confirmMasterKey(key []byte) bool {
	confirm := readMasterKey()
	return bytes.Equal(key, confirm)
}
