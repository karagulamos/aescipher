package padding

import (
	"bytes"
	"errors"
)

const (
	// PKCS7 padding option
	PKCS7 string = "PKCS7"

	// PKCS5 padding optiion
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

// PKCS7Padding PKCS7 padding strategy for AES
type PKCS7Padding struct{}

// Apply applies PKCS7 padding
func (pkcs PKCS7Padding) Apply(unpadded []byte, blockSize int) []byte {
	padding := (blockSize - len(unpadded)%blockSize)
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(unpadded, padtext...)
}

// Undo removes PKCS7 padding
func (pkcs PKCS7Padding) Undo(padded []byte) []byte {
	length := len(padded)
	unpadding := int(padded[length-1])
	return padded[:(length - unpadding)]
}

// GetPadding factory method of padding strategies
func GetPadding(option string) (IPaddingStrategy, error) {
	switch option {
	case PKCS5, PKCS7:
		return PKCS7Padding{}, nil
	}

	return NullPadding{}, errors.New("error: invalid padding option")
}
