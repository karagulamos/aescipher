package aescipher

import "testing"

// TestGetPaddingReturnsErrorWhenSuppliedInvalidOption ...
func TestGetPaddingReturnsErrorWhenSuppliedInvalidOption(t *testing.T) {
	_, err := GetPadding("")

	if err == nil {
		t.Fail()
	}
}

// TestGetPaddingReturnsPaddingForValidOption ...
func TestGetPaddingReturnsPaddingForValidOption(t *testing.T) {
	_, err := GetPadding(PKCS5)

	if err != nil {
		t.Fail()
	}
}
