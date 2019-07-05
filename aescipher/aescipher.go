package aescipher

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"errors"
)

// AesCipher provides functionalities to encrypt text using AES
type AesCipher struct {
	iv      []byte
	key     []byte
	padding IPaddingStrategy
}

// New constructs a new instance of AesCipher
func New(iv, key string, padding IPaddingStrategy) *AesCipher {
	return &AesCipher{
		[]byte(iv),
		[]byte(key),
		padding,
	}
}

// Encrypt encrypts a text using AES
func (ac *AesCipher) Encrypt(plainText string) (string, error) {
	block, err := aes.NewCipher(ac.key)

	if err != nil {
		return "", err
	}

	paddedBytes := ac.padding.Apply([]byte(plainText), aes.BlockSize)

	ciphertext := make([]byte, len(paddedBytes))
	mode := cipher.NewCBCEncrypter(block, ac.iv)
	mode.CryptBlocks(ciphertext, paddedBytes)

	return hex.EncodeToString(ciphertext), nil
}

// Decrypt decrypts a text using AES
func (ac *AesCipher) Decrypt(encryptedText string) (string, error) {
	decodedText, _ := hex.DecodeString(encryptedText)

	block, err := aes.NewCipher(ac.key)

	if err != nil {
		return "", err
	}

	if len(decodedText) < aes.BlockSize {
		return "", errors.New("cipher text too short")
	}

	decrypted := make([]byte, len(decodedText))

	mode := cipher.NewCBCDecrypter(block, ac.iv)
	mode.CryptBlocks(decrypted, decodedText)

	return string(ac.padding.Undo(decrypted)), nil
}
