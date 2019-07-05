package examples

import (
	"fmt"
	"log"

	"github.com/karagulamos/aescipher/aescipher"
)

var iv = `5OMTZPbytOmFlCAs`
var key = `6gTISUYvekDcgDwO`

func main() {
	padding, err := aescipher.GetPadding(aescipher.PKCS5)

	if err != nil {
		fmt.Println(err.Error())
		return
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
