package encrypt

import (
	"bytes"
	"fmt"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func TestCheckSum(t *testing.T) {
	data := []byte("hello")
	// SHA256 of "hello"
	expected := "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
	result := CheckSum(data)
	if result != expected {
		t.Errorf("Expected checksum %s, got %s", expected, result)
	}
}

func TestHashing(t *testing.T) {
	prefixBcrypt := getPrefix(HashModeBcrypt)
	prefixArgon2 := getPrefix(HashModeArgon2)

	data := []byte("my_super_secure_password")
	wrongData := []byte("wrong_password")

	tests := []struct {
		name         string
		hashFunc     func() ([]byte, error)
		expectPrefix string
	}{
		{
			name: "Bcrypt",
			hashFunc: func() ([]byte, error) {
				return CreateHash(Bcrypt{bcrypt.MinCost}, data) // cost 10
			},
			expectPrefix: prefixBcrypt,
		},
		{
			name: "Argon2",
			hashFunc: func() ([]byte, error) {
				// use default params
				return CreateHash(Argon2{}, data)
			},
			expectPrefix: prefixArgon2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hashedData, err := tt.hashFunc()
			if err != nil {
				t.Fatalf("CreateHash error: %v", err)
			}

			if !bytes.HasPrefix(hashedData, []byte(tt.expectPrefix)) {
				t.Errorf("Expected prefix %q, got %q", tt.expectPrefix, hashedData[:prefixLen])
			}
			fmt.Println(string(hashedData))
			fmt.Println(string(hashedData[prefixLen:]))

			// Correct password
			if err := CompareHash(data, hashedData); err != nil {
				t.Errorf("CompareHash with correct data failed: %v", err)
			}

			// Wrong password
			if err := CompareHash(wrongData, hashedData); err == nil {
				t.Error("CompareHash with incorrect data succeeded, expected error")
			}
		})
	}
}

func TestCompareHashShortData(t *testing.T) {
	err := CompareHash([]byte("data"), []byte("h"))
	if err == nil {
		t.Error("Expected error for short hash data, got nil")
	}
}
