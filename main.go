package main

import (
	"bytes"
	"fmt"
	"github.com/cep21/xdgbasedir"
	"github.com/hexid/warded/wutil"
	"gopkg.in/alecthomas/kingpin.v2"
	"os"
	"path"
	"syscall"
)

var (
	app      = kingpin.New("warded", "A minimal passphrase manager using Chacha20-Poly1305")
	wardName = app.Flag("ward", "Ward group name").Default("default").String()

	show              = app.Command("show", "Show passphrase")
	showOnlyFirstLine = show.Flag("first", "Show only the first line").Bool()
	showPassName      = show.Arg("passName", "Passphrase name").Required().String()

	edit         = app.Command("edit", "Edit passphrase")
	editPassName = edit.Arg("passName", "Passphrase name").Required().String()

	generate         = app.Command("generate", "Generate passphrase")
	generateLength   = generate.Arg("passLength", "Passphrase length").Uint()
	generatePassName = generate.Arg("passName", "Passphrase name").String()

	list = app.Command("list", "List passphrases")

	rekey = app.Command("rekey", "Rekey all passphrases in the ward")
)

func main() {
	if err := mainError(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func mainError() error {
	memErr := syscall.Mlockall(syscall.MCL_CURRENT | syscall.MCL_FUTURE)
	if memErr != nil {
		return memErr
	}

	dataDir, err := xdgbasedir.DataHomeDirectory()
	if err != nil {
		return err
	}
	wardedDataDir := path.Join(dataDir, "warded")

	commands := kingpin.MustParse(app.Parse(os.Args[1:]))

	wardDir := path.Join(wardedDataDir, *wardName)
	os.MkdirAll(wardDir, 0700)

	switch commands {
	case show.FullCommand():
		pass := GetPassphrase(path.Join(wardDir, *showPassName))
		if *showOnlyFirstLine {
			ind := bytes.IndexByte(pass, '\n') + 1
			pass = pass[:ind]
		}
		fmt.Println(string(pass[:]))

	case edit.FullCommand():
		EditPassphrase(wardDir, *editPassName)

	case generate.FullCommand():
		randType := wutil.RandAlpha | wutil.RandNum | wutil.RandSpecial
		randStr := wutil.RandStr(*generateLength, randType)

		if *generatePassName == "" {
			fmt.Printf("Passphrase: %s\n", randStr)
		} else if oldPass, err := ReplacePassphrase(wardDir, *generatePassName, randStr); err != nil {
			return err
		} else {
			fmt.Printf("Old: %s\nNew: %s\n", oldPass, randStr)
		}

	case list.FullCommand():
		passphrases := getPassphrases(wardDir)
		for passName, _ := range passphrases {
			fmt.Println(passName)
		}

	case rekey.FullCommand():
		return RekeyWard(wardedDataDir, *wardName)
	}

	return nil
}
