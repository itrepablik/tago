![Tago](https://user-images.githubusercontent.com/58651329/79629301-1d414a00-817b-11ea-9e57-af0dd776d4e9.png)
Use **tago** to encrypt any classified text with your especial secret keys for mixture to formulate the encrypted text and able to decrypt it with the same secret key when you need to extract the whole classified text back to a normal phrase.

# Installation
```
go get -u github.com/itrepablik/tago
```

# Usage
```
package main

import (
	"fmt"

	"github.com/itrepablik/itrlog"
	"github.com/itrepablik/tago"
)

// Keep this secret key with you.
const secretKey string = "abc&1*~#^2^#s0^=)^^7%b34"

func main() {
	phrase := "Hello World!"

	// To encrypt the classified text
	encText, err := tago.Encrypt(phrase, secretKey)
	if err != nil {
		itrlog.Fatalw("error encrypting your classified text: ", err)
	}
	fmt.Println("encrypted text: ", encText)

	// To decrypt the encrypted classified text
	dText, err := tago.Decrypt(encText, secretKey)
	if err != nil {
		itrlog.Fatalw("error decrypting your encrypted text: ", err)
	}
	fmt.Println("decrypted text: ", dText)
}
```

# License
Code is distributed under MIT license, feel free to use it in your proprietary projects as well.
