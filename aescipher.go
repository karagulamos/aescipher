package aescipher

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"errors"

	"github.com/karagulamos/aescipher/padding"
)

const (
	errorInvalidPadding     = "error: invalid padding"
	errorCipherTextTooShort = "error: cipher text too short"
)

// AesCipher provides functionalities to encrypt text using AES
type AesCipher struct {
	iv      []byte
	key     []byte
	padding padding.IPaddingStrategy
}

// New constructs a new instance of AesCipher
func New(iv, key string, paddingStrategy ...padding.IPaddingStrategy) *AesCipher {
	if len(paddingStrategy) == 0 {
		padding, _ := padding.GetPadding(padding.PKCS7)
		return &AesCipher{[]byte(iv), []byte(key), padding}
	}

	return &AesCipher{[]byte(iv), []byte(key), paddingStrategy[0]}
}

// Encrypt encrypts a text using AES
func (ac *AesCipher) Encrypt(plainText string) (string, error) {
	block, err := aes.NewCipher(ac.key)

	if err != nil {
		return "", err
	}

	padded := ac.padding.Apply([]byte(plainText), aes.BlockSize)

	if len(padded) == 0 {
		return "", errors.New(errorInvalidPadding)
	}

	ciphertext := make([]byte, len(padded))

	mode := cipher.NewCBCEncrypter(block, ac.iv)
	mode.CryptBlocks(ciphertext, padded)

	return hex.EncodeToString(ciphertext), nil
}

// Decrypt decrypts a text using AES
func (ac *AesCipher) Decrypt(encryptedText string) (string, error) {
	decoded, _ := hex.DecodeString(encryptedText)

	block, err := aes.NewCipher(ac.key)

	if err != nil {
		return "", err
	}

	if len(decoded) < aes.BlockSize {
		return "", errors.New(errorCipherTextTooShort)
	}

	decrypted := make([]byte, len(decoded))

	mode := cipher.NewCBCDecrypter(block, ac.iv)
	mode.CryptBlocks(decrypted, decoded)

	unpadded := ac.padding.Undo(decrypted)

	if len(unpadded) == 0 {
		return "", errors.New(errorInvalidPadding)
	}

	return string(unpadded), nil
}
