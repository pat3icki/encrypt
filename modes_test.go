package encrypt

import (
	"bytes"
	"testing"
)

// Test to verify prefix is at beginning
func TestEncryptPrefix(t *testing.T) {
	prefixAES256 := getPrefix(EncryptModeAESGCM)

	ag := &AES_GCM{Key: make([]byte, 32)}
	data := []byte("test data")

	result, err := ag._encrypt(data)
	if err != nil {
		t.Fatal(err)
	}

	// Verify prefix is at beginning
	if !bytes.HasPrefix(result, []byte(prefixAES256)) {
		t.Errorf("Prefix not at beginning. Got: %x", result[:prefixLen])
	}

	// Verify length
	expectedLen := prefixLen + 12 + len(data) + 16 // 12 for nonce, 16 for tag
	if len(result) != expectedLen {
		t.Errorf("Expected length %d, got %d", expectedLen, len(result))
	}
}
