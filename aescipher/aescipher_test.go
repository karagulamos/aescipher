package aescipher

import "testing"

// TestEncryptReturnsErrorWhenSuppliedEmptyKeyAndIV ...
func TestEncryptReturnsErrorWhenSuppliedEmptyKeyAndIV(t *testing.T) {
	padding, _ := GetPadding(PKCS5)
	aescipher := New("", "", padding)

	_, err := aescipher.Encrypt("text to encrypt")

	if err == nil {
		t.Fail()
	}
}

// TestEncryptReturnsValidEncryptedText ...
func TestEncryptReturnsValidEncryptedText(t *testing.T) {
	padding, _ := GetPadding(PKCS5)
	aescipher := New("0123456789ABCDEF", "0123456789ABCDEF", padding)

	encrypted, _ := aescipher.Encrypt("1")

	if encrypted != "3389acc0972916a993a62ad749d9db18" {
		t.Fail()
	}
}

// TestDecryptReturnsErrorWhenSuppliedEmptyKeyAndIV ...
func TestDecryptReturnsErrorWhenSuppliedEmptyKeyAndIV(t *testing.T) {
	padding, _ := GetPadding(PKCS5)
	aescipher := New("", "", padding)

	_, err := aescipher.Decrypt("3389acc0972916a993a62ad749d9db18")

	if err == nil {
		t.Fail()
	}
}

// TestDecryptReturnsValidDecryptedText ...
func TestDecryptReturnsValidDecryptedText(t *testing.T) {
	padding, _ := GetPadding(PKCS5)
	aescipher := New("0123456789ABCDEF", "0123456789ABCDEF", padding)

	decrypted, _ := aescipher.Decrypt("3389acc0972916a993a62ad749d9db18")

	if decrypted != "1" {
		t.Fail()
	}
}
