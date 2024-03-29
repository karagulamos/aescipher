package aescipher

import (
	"testing"

	"github.com/karagulamos/aescipher/padding"
)

// TestEncryptReturnsErrorGivenInvalidKeyAndIV ...
func TestEncryptReturnsErrorGivenInvalidKeyAndIV(t *testing.T) {
	padding, _ := padding.GetPadding(padding.PKCS7)
	aescipher := New("", "", padding)

	_, err := aescipher.Encrypt("text to encrypt")

	if err == nil {
		t.Fail()
	}
}

// TestEncryptReturnsErrorGivenInvalidPaddingOption ...
func TestEncryptReturnsErrorGivenInvalidPaddingOption(t *testing.T) {
	padding, _ := padding.GetPadding("")
	aescipher := New("0123456789ABCDEF", "0123456789ABCDEF", padding)

	_, err := aescipher.Encrypt("1")

	if err == nil {
		t.Fail()
	}
}

// TestEncryptReturnsValidEncryptedText ...
func TestEncryptReturnsValidEncryptedText(t *testing.T) {
	padding, _ := padding.GetPadding(padding.PKCS7)
	aescipher := New("0123456789ABCDEF", "0123456789ABCDEF", padding)

	encrypted, _ := aescipher.Encrypt("1")

	if encrypted != "3389acc0972916a993a62ad749d9db18" {
		t.Fail()
	}
}

// TestDecryptReturnsErrorGivenInvalidKeyAndIV ...
func TestDecryptReturnsErrorGivenInvalidKeyAndIV(t *testing.T) {
	padding, _ := padding.GetPadding(padding.PKCS7)
	aescipher := New("", "", padding)

	_, err := aescipher.Decrypt("3389acc0972916a993a62ad749d9db18")

	if err == nil {
		t.Fail()
	}
}

// TestDecryptReturnsErrorGivenInvalidCipherTextLength ...
func TestDecryptReturnsErrorGivenInvalidCipherTextLength(t *testing.T) {
	padding, _ := padding.GetPadding(padding.PKCS7)
	aescipher := New("0123456789ABCDEF", "0123456789ABCDEF", padding)

	correct := "3389acc0972916a993a62ad749d9db18"
	invalid := correct[0 : len(correct)-2]

	_, err := aescipher.Decrypt(invalid)

	if err == nil {
		t.Fail()
	}
}

// TestDecryptReturnsErrorGivenInvalidPaddingOption ...
func TestDecryptReturnsErrorGivenInvalidPaddingOption(t *testing.T) {
	padding, _ := padding.GetPadding("")
	aescipher := New("0123456789ABCDEF", "0123456789ABCDEF", padding)

	_, err := aescipher.Decrypt("3389acc0972916a993a62ad749d9db18")

	if err == nil {
		t.Fail()
	}
}

// TestDecryptReturnsValidDecryptedText ...
func TestDecryptReturnsValidDecryptedText(t *testing.T) {
	padding, _ := padding.GetPadding(padding.PKCS7)
	aescipher := New("0123456789ABCDEF", "0123456789ABCDEF", padding)

	decrypted, _ := aescipher.Decrypt("3389acc0972916a993a62ad749d9db18")

	if decrypted != "1" {
		t.Fail()
	}
}
