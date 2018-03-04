package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path"
	"regexp"
	"sort"

	"camlistore.org/pkg/misc/pinentry"

	"github.com/cep21/xdgbasedir"
	"github.com/daviddengcn/go-colortext"
	"github.com/hexid/go-randstr"
	"github.com/hexid/warded"
	"gopkg.in/alecthomas/kingpin.v2"
)

var (
	ward warded.Ward

	pinRequest = pinentry.Request{
		Desc:   "Warded Master Key",
		Prompt: "Master Key",
	}
	masterKey warded.Key

	app        = kingpin.New("warded", "A minimal passphrase manager using Chacha20-Poly1305")
	help       = app.HelpFlag.Short('h')
	wardName   = app.Flag("ward", "Ward group name").Short('w').Default("default").Envar("WARDED_NAME").String()
	configPath = app.Flag("config", "Config file").Short('c').Envar("WARDED_CONFIG").String()
	dataPath   = app.Flag("data", "Data directory").Short('d').Envar("WARDED_DATA").String()

	copy             = app.Command("copy", "Copy a passphrase").Alias("cp")
	copySrcPassName  = copy.Arg("srcPassName", "Source passphrase name").HintAction(listWard).Required().String()
	copyDestPassName = copy.Arg("destPassName", "Destination passphrase name").Required().String()

	data         = app.Command("data", "Show remainder of lines starting with a given regexp").Action(loadMasterKey)
	dataMaxMatch = data.Flag("max", "Match at most <MAX> line(s)").Short('m').Uint()
	dataPassName = data.Arg("passName", "Passphrase name").HintAction(listWard).Required().String()
	dataRegexp   = data.Arg("regexp", "String that matches against the start of each line").Required().Regexp()

	edit         = app.Command("edit", "Edit passphrase").Action(loadMasterKey)
	editPassName = edit.Arg("passName", "Passphrase name").HintAction(listWard).Required().String()

	generate         = app.Command("generate", "Generate passphrase")
	generateSpecial  = generate.Flag("special", "Allowed special characters").Short('s').Default("\000").String()
	generateLength   = generate.Arg("passLength", "Passphrase length").Required().Uint()
	generatePassName = generate.Arg("passName", "Passphrase name").HintAction(listWard).Action(loadMasterKey).String()

	grep           = app.Command("grep", "Search for text in the ward").Action(loadMasterKey)
	grepIgnoreCase = grep.Flag("icase", "Ignore case when matching").Short('i').Bool()
	grepRegexp     = grep.Arg("regexp", "Search term").Required().Regexp()
	grepPath       = grep.Arg("path", "Search path").String()

	list     = app.Command("list", "List passphrases").Alias("ls")
	listPath = list.Arg("path", "List path").String()

	move             = app.Command("move", "Move a passphrase").Alias("mv")
	moveSrcPassName  = move.Arg("srcPassName", "Source passphrase name").Required().String()
	moveDestPassName = move.Arg("destPassName", "Destination passphrase name").Required().String()

	rekey = app.Command("rekey", "Rekey all passphrases in the ward").Action(loadMasterKey)

	remove         = app.Command("remove", "Remove a passphrase").Alias("rm")
	removePassName = remove.Arg("passName", "Passphrase name").HintAction(listWard).Required().String()

	show          = app.Command("show", "Show passphrase").Action(loadMasterKey)
	showOnlyFirst = show.Flag("first", "Show only the first line").Short('1').Bool()
	showPassName  = show.Arg("passName", "Passphrase name").HintAction(listWard).Required().String()

	stats     = app.Command("stats", "Get statistics on passphrases in the ward").Action(loadMasterKey)
	statsJSON = stats.Flag("json", "Print the unprocessed statistics as JSON").Bool()
	statsPath = stats.Arg("path", "Statistics path").String()
)

func listWard() []string {
	list, _ := ward.List("")
	return list
}

func loadMasterKey(ctx *kingpin.ParseContext) (err error) {
	masterKey, err = requestKey()
	return
}
func requestKey() (key warded.Key, err error) {
	if keyStr, err := pinRequest.GetPIN(); err == nil {
		key = []byte(keyStr)
		err = key.Lock()
	} else if err == pinentry.ErrCancel {
		err = fmt.Errorf("Exiting. Pinentry cancelled")
	}
	return
}

func main() {
	if err := mainError(); err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
}

func getWard(ctx *kingpin.ParseContext) error {
	var err error

	config := warded.Config{
		Ward: warded.DefaultWardConfig(),
	}

	if *configPath == "" {
		if *configPath, err = xdgbasedir.ConfigHomeDirectory(); err != nil {
			return err
		}
		*configPath = path.Join(*configPath, "warded.json")
	}
	if configData, cfgErr := ioutil.ReadFile(*configPath); cfgErr == nil {
		if cfgErr = json.Unmarshal(configData, &config); cfgErr != nil {
			return cfgErr
		}
	}

	if *dataPath == "" {
		var dataDir string
		if dataDir, err = xdgbasedir.DataHomeDirectory(); err != nil {
			return err
		}
		*dataPath = path.Join(dataDir, "warded")
	}

	wardDir := path.Join(*dataPath, *wardName)
	if err = os.MkdirAll(wardDir, 0700); err != nil {
		return err
	}

	ward = warded.NewWard()
	ward.Config = config.GetWardConfig(*wardName)
	ward.Dir = wardDir

	return err
}

func mainError() (err error) {
	app.PreAction(getWard)
	commands := kingpin.MustParse(app.Parse(os.Args[1:]))

	if masterKey != nil {
		defer masterKey.Unlock()
	}

	ward.SetKey(masterKey)

	switch commands {
	case copy.FullCommand():
		var srcFile, destFile *os.File
		var srcStat os.FileInfo

		if srcFile, err = os.Open(ward.Path(*copySrcPassName)); err != nil {
			return
		}
		defer srcFile.Close()
		srcStat, err = srcFile.Stat()
		if err != nil {
			return
		}

		destFile, err = os.OpenFile(ward.Path(*copyDestPassName),
			os.O_CREATE|os.O_TRUNC|os.O_WRONLY, srcStat.Mode())
		if err != nil {
			return
		}
		defer destFile.Close()

		if _, err = io.Copy(destFile, srcFile); err == nil {
			err = destFile.Close()
		}

	case data.FullCommand():
		var pass []byte
		if pass, err = ward.Get(*dataPassName); err == nil {
			lines := bytes.Split(pass, []byte("\n"))
			maxLines := *dataMaxMatch
			check := maxLines > 0
			regexpStr := fmt.Sprintf("^(?i)(?:%s)\\s*(.*)", (*dataRegexp).String())
			fullRegexp := regexp.MustCompile(regexpStr)

			for _, line := range lines {
				if groups := fullRegexp.FindSubmatch(line); len(groups) > 1 {
					fmt.Println(string(groups[len(groups)-1]))

					maxLines--
					if check && maxLines > 0 {
						break
					}
				}
			}
		}

	case edit.FullCommand():
		var pass, newPass []byte
		if pass, err = ward.GetOrCheck(*editPassName); err != nil {
			return
		}

		if newPass, err = editorTemp(pass); err == nil {
			if bytes.Equal(pass, newPass) {
				err = fmt.Errorf("Passphrase unchanged")
			} else if err = ward.Edit(*editPassName, newPass); err == nil {
				fmt.Println("Modified passphrase")
			}
		}

	case generate.FullCommand():
		var oldPass []byte
		var randStr []byte
		var availRand string

		if *generateSpecial != "\000" {
			availRand = (randstr.AlphaASCII | randstr.DigitASCII).String() + *generateSpecial

			// strip out any duplicate characters
			availRand = string(uniqRunes([]rune(availRand)))
		} else {
			availRand = randstr.RandASCII.String()
		}

		if randStr, err = randstr.Random(*generateLength, availRand); err == nil {
			if *generatePassName == "" {
				fmt.Printf("Passphrase: %s\n", randStr)
			} else if oldPass, err = ward.Update(*generatePassName, randStr); err == nil {
				fmt.Printf("Old: %s\nNew: %s\n", oldPass, randStr)
			}
		}

	case grep.FullCommand():
		var results []warded.SearchResult
		if *grepIgnoreCase {
			*grepRegexp, err = regexp.Compile(fmt.Sprintf("(?i)%s", (*grepRegexp).String()))
			if err != nil {
				return err
			}
		}
		results, err = ward.Search(*grepPath, *grepRegexp)
		for _, res := range results {
			ct.Foreground(ct.Blue, false)
			fmt.Printf("%s:%d ", res.Passphrase, res.LineNum+1)
			ct.ResetColor()
			fmt.Printf("%s", res.Line[:res.IndexStart])
			ct.Foreground(ct.Red, false)
			fmt.Printf("%s", res.Line[res.IndexStart:res.IndexEnd])
			ct.ResetColor()
			fmt.Printf("%s\n", res.Line[res.IndexEnd:])
		}

	case list.FullCommand():
		var passphrases []string
		if passphrases, err = ward.List(*listPath); err == nil {
			sort.Strings(passphrases)

			for _, name := range passphrases {
				fmt.Println(name)
			}
		}

	case move.FullCommand():
		err = os.Rename(ward.Path(*moveSrcPassName), ward.Path(*moveDestPassName))

	case rekey.FullCommand():
		var newMasterKey warded.Key
		newMasterKey, err = requestKey()
		if newMasterKey != nil {
			defer newMasterKey.Unlock()
		}
		if err == nil {
			err = ward.Rekey(newMasterKey, *dataPath)
		}

	case remove.FullCommand():
		err = os.Remove(ward.Path(*removePassName))

	case show.FullCommand():
		var pass []byte
		if pass, err = ward.Get(*showPassName); err == nil {
			if *showOnlyFirst {
				if ind := bytes.IndexByte(pass, '\n') + 1; ind != 0 {
					pass = pass[:ind]
				}
			}
			fmt.Println(string(pass[:]))
		}

	case stats.FullCommand():
		var statistics *warded.Statistics
		if statistics, err = ward.Stats(*statsPath); err == nil {
			if *statsJSON {
				var jsonStats []byte
				jsonStats, err = json.Marshal(statistics)
				fmt.Printf("%s\n", string(jsonStats))
			} else {
				lengthCounts := make([]int, statistics.MaxLength+1)

				fmt.Printf("Duplicates:\n")
				foundDupes := false
				for _, group := range statistics.Groups {
					if len(group.Passphrases) > 1 {
						fmt.Printf("\t%d %v\n", group.Length, group.Passphrases)
						foundDupes = true
					}

					groupCount := len(group.Passphrases)
					lengthCounts[group.Length] += groupCount
				}
				if !foundDupes {
					fmt.Printf("\tNone found\n")
				}

				fmt.Printf("Lengths:\n")
				for length, count := range lengthCounts {
					if count > 0 {
						fmt.Printf("\t%d: %d\n", length, count)
					}
				}

				fmt.Printf("Passphrase count: %d\n", statistics.Count)
				fmt.Printf("Average passphrase length: %f\n",
					float64(statistics.SumLength)/float64(statistics.Count))
			}
		}
	}

	return
}
