package padding

import (
	"testing"
)

// TestGetPaddingReturnsErrorGivenInvalidPaddingOption ...
func TestGetPaddingReturnsErrorGivenInvalidPaddingOption(t *testing.T) {
	_, err := GetPadding("")

	if err == nil {
		t.Fail()
	}
}

// TestApplyReturnsEmptySliceGivenInvalidPaddingOption ...
func TestApplyReturnsEmptySliceGivenInvalidPaddingOption(t *testing.T) {
	padding, _ := GetPadding("")

	result := padding.Apply([]byte("123456789ABCDEF"), 16)

	if len(result) != 0 {
		t.Fail()
	}
}

// TestApplyReturnsCorrectPaddingLength ...
func TestApplyReturnsCorrectPaddingLength(t *testing.T) {
	padding, _ := GetPadding(PKCS7)
	expectedLength := 11

	padded := padding.Apply([]byte("12345"), expectedLength)

	if len(padded) != expectedLength {
		t.Fail()
	}
}

// TestUndoReturnsEmptySliceGivenInvalidPaddingOption ...
func TestUndoReturnsEmptySliceGivenInvalidPaddingOption(t *testing.T) {
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
	padding, _ := GetPadding(PKCS7)
	original := []byte("12345")

	padded := padding.Apply(original, 11)
	unpadded := padding.Undo(padded)

	if len(original) != len(unpadded) {
		t.Fail()
	}
}
