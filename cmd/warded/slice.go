package main

func uniqRunes(str []rune) []rune {
	seen := make(map[rune]struct{}, len(str))
	c := 0
	for _, v := range str {
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		str[c] = v
		c++
	}
	return str[:c]
}
