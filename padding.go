package aescipher

import (
	"bytes"
	"errors"
)

const (
	// PKCS5 padding option
	PKCS5 string = "PKCS5"
)

// IPaddingStrategy provides a common base for different AES padding strategies
type IPaddingStrategy interface {
	Apply(unpadded []byte, blockSize int) []byte
	Undo(padded []byte) []byte
}

// NullPadding default padding strategy when no valid option is passed to the factory method
type NullPadding struct{}

// Apply applies no padding
func (pkcs NullPadding) Apply(unpadded []byte, blockSize int) []byte {
	return []byte{}
}

// Undo removes no padding
func (pkcs NullPadding) Undo(padded []byte) []byte {
	return []byte{}
}

// PKCS5Padding PCKS5 padding strategy for AES
type PKCS5Padding struct{}

// Apply applies PKCS5 padding
func (pkcs PKCS5Padding) Apply(unpadded []byte, blockSize int) []byte {
	padding := (blockSize - len(unpadded)%blockSize)
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(unpadded, padtext...)
}

// Undo removes PKCS5 padding
func (pkcs PKCS5Padding) Undo(padded []byte) []byte {
	length := len(padded)
	unpadding := int(padded[length-1])
	return padded[:(length - unpadding)]
}

// GetPadding factory method of padding strategies
func GetPadding(option string) (IPaddingStrategy, error) {
	switch option {
	case PKCS5:
		return PKCS5Padding{}, nil
	}

	return NullPadding{}, errors.New("error: invalid padding option")
}
