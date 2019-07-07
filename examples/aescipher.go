package examples

import (
	"fmt"
	"log"

	"github.com/karagulamos/aescipher"
	"github.com/karagulamos/aescipher/padding"
)

var iv = `5OMTZPbytOmFlCAs`
var key = `6gTISUYvekDcgDwO`

func main() {
	padding, err := padding.GetPadding(padding.PKCS7)

	if err != nil {
		log.Fatal(err)
	}

	aescipher := aescipher.New(iv, key, padding)

	plainText := `{"user":"THIRDPARTY","px":"V@f@3v1lk4Op*7ID","rx":"j0sr%Zk6^JB4v~Kc"}`

	fmt.Printf("plaintext: %s\n", plainText)

	cipherText, err := aescipher.Encrypt(plainText)

	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("encrypted: %s\n", cipherText)

	decrypted, err := aescipher.Decrypt(cipherText)

	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("decrypted: %s\n", decrypted)
}
