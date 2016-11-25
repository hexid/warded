package wutil

import (
	"crypto/rand"
)

type RandStrDict uint32

const (
	RandAlpha        RandStrDict = 1 << 0
	RandNum          RandStrDict = 1 << 1
	RandSpecial      RandStrDict = 1 << 2
	RandExtraSpecial RandStrDict = 1 << 3
)

func RandStr(strSize uint, randType RandStrDict) string {
	dictionary := ""

	if randType&RandAlpha > 0 {
		dictionary += "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	}
	if randType&RandNum > 0 {
		dictionary += "0123456789"
	}
	if randType&RandSpecial > 0 {
		dictionary += " !\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"
	}

	dictLen := byte(len(dictionary))

	randBytes := make([]byte, strSize)
	rand.Read(randBytes)
	for k, v := range randBytes {
		randBytes[k] = dictionary[v%dictLen]
	}
	return string(randBytes)
}
