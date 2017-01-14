package main

import (
	"bytes"
	"io"
	"os"
	"os/exec"
)

func editorTemp(pass []byte) ([]byte, error) {
	editor := os.Getenv("EDITOR")
	if editor == "" {
		editor = "/usr/bin/env vi"
	}

	secFile, secErr := GetMemFile("warded")
	if secErr != nil {
		return nil, secErr
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
		return nil, cmdErr
	}

	readFile, err := os.Open(secFile.Name())
	if err != nil {
		return nil, err
	}
	defer readFile.Close()

	buf := new(bytes.Buffer)
	next := make([]byte, 512)
	for {
		n, err := readFile.Read(next)
		if err != nil && err != io.EOF {
			return nil, err
		}
		if n == 0 {
			break
		}
		buf.Write(next[:n])
	}

	return buf.Bytes(), nil
}
