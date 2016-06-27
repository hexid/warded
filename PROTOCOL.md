# warded
## A minimal passphrase manager using Chacha20-Poly1305

### Not everything here has been implemented
### This specification is likely to change

### Terminology

- ward - a repository of passphrases


### Directory/File Structure

##### All files/directories will only be readable by the current user, unless `groupRead` is `true (default: false)`
##### The .warded file must have 600 permissions

- `${XDG_DATA_HOME:-$HOME/.local/share}/warded/{wardName}/`
	- `.warded`
	```
	{
		"algorithms": {
			"derivation": "scrypt",
			"encryption": "chacha20-poly1305"
		},
		"verifyMasterKey": true,
		"groupRead": false
	}
	```

	- `[{groups}/]{passName}`
	```
	{
		"nonce": base64-encoded chacha20 nonce,
		"salt": base64-encoded derivation salt,
		"ciphertext": base64-encoded ciphertext,
	}
	```


### Master Key Verification

##### Verification is not done when `masterKey.verify` is `false` (default: `true`)

##### Note: This is done when creating a new passphrase to ensure that all passphrases in a ward are encrypted with the same master key

- If `masterKey.verify` is false, we will create a visual of the hash and ask the user to verify it:
```
key := scrypt(masterKey, masterKey.salt, 16384, 8, 1, 32)
visual := visualKey(key)
fmt.Printf("%s\nIs this correct? (y/N)", visual)
var res bool
fmt.Scanf("%c", &res)
```

- Otherwise, we will verify the key by attempting to decrypt a random existing passphrase:
```
key := scrypt(masterKey, randPass.salt, 16384, 8, 1, 32)
aead := chacha20poly1305(key)
aead.Open(null, randPass.nonce, randPass.ciphertext)
```


### Encryption

```
key := scrypt(masterKey, pass.salt, 16384, 8, 1, 32)
aead := chacha20poly1305(key)
nonce := make([]byte, 8)
rand.Read(nonce)

var ciphertext, plaintext
aead.Seal(ciphertext, nonce, plaintext)
```


### Decryption

```
key := scrypt(masterKey, pass.salt, 16384, 8, 1, 32)
aead := chacha20poly1305(key)

var plaintext
aead.Open(plaintext, pass.nonce, pass.ciphertext)
```
