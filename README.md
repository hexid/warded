# warded
## A minimal passphrase manager using Chacha20-Poly1305

### This project is still in active development and is likely to change drastically in the time leading up to a 1.0 release

### Usage

`warded [command] [options]`


### Options

- `-w {wardName}`
	- Select a ward to operate on
	- Defaults to `default` if not supplied


### Commands

- `edit <passName>`
	- Edit/create a passphrase using `$EDITOR`

- `generate <passName> <passLength>`
	- Generates a new passphrase
	- If `passName` already exists, only the first line will be replaced

- `ls`, `list`
	- List passphrases in a ward

- `rekey`
	- Replaces the existing master key and a new master key
	- This operation will create a new temporary ward to ensure that the existing ward is not left in an inconsistent state in the case of failure/interruption

- `show <passName>`
	- Prints the given passphrase

