package aescipher

import (
	"testing"
)

// TestGetPaddingReturnsErrorWhenPaddingOptionIsInvalid ...
func TestGetPaddingReturnsErrorWhenPaddingOptionIsInvalid(t *testing.T) {
	_, err := GetPadding("")

	if err == nil {
		t.Fail()
	}
}

// TestApplyReturnsEmptySliceWhenPaddingOptionIsInvalid ...
func TestApplyReturnsEmptySliceWhenPaddingOptionIsInvalid(t *testing.T) {
	padding, _ := GetPadding("")

	result := padding.Apply([]byte("123456789ABCDEF"), 16)

	if len(result) != 0 {
		t.Fail()
	}
}

// TestApplyReturnsCorrectPaddingLength ...
func TestApplyReturnsCorrectPaddingLength(t *testing.T) {
	padding, _ := GetPadding(PKCS5)

	result := padding.Apply([]byte("12345"), 11)

	if len(result) != 11 {
		t.Fail()
	}
}

// TestUndoReturnsEmptySliceWhenPaddingOptionIsInvalid ...
func TestUndoReturnsEmptySliceWhenPaddingOptionIsInvalid(t *testing.T) {
	padding, _ := GetPadding("")
	original := []byte("12345")

	padded := padding.Apply(original, 11)
	unpadded := padding.Undo(padded)

	if len(unpadded) != 0 {
		t.Fail()
	}
}

// TestUndoReturnsCorrectUnpaddedLength ...
func TestUndoReturnsCorrectUnpaddedLength(t *testing.T) {
	padding, _ := GetPadding(PKCS5)
	original := []byte("12345")

	padded := padding.Apply(original, 11)
	unpadded := padding.Undo(padded)

	if len(original) != len(unpadded) {
		t.Fail()
	}
}
