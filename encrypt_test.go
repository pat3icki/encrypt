package encrypt

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"testing"

	"golang.org/x/crypto/chacha20poly1305"
)

func TestEncryptionDecryption(t *testing.T) {
	prefixAES256 := getPrefix(EncryptModeAESGCM)
	prefixXChaCha := getPrefix(EncryptModeXChaCha_Poly1305)
	prefixBranca := getPrefix(EncryptModeBranca)
	prefixCipher := getPrefix(EncryptModeCipher)

	key32 := []byte("12345678901234567890123456789012") // 32 bytes
	tests := []struct {
		name         string
		mode         Encryptor
		key          []byte
		expectPrefix string
	}{

		{
			name:         "AES GCM",
			mode:         &AES_GCM{Key: key32},
			key:          key32,
			expectPrefix: string(prefixAES256),
		},
		{
			name:         "XChaCha_Poly1305",
			mode:         &XChaCha_Poly1305{Key: key32},
			key:          key32,
			expectPrefix: string(prefixXChaCha),
		},
		{
			name:         "Branca",
			mode:         &Branca{Password: string(key32)},
			key:          key32,
			expectPrefix: string(prefixBranca),
		},
		{
			name: "Cipher (AES-GCM)",
			mode: func() Encryptor {
				block, err := aes.NewCipher(key32)
				if err != nil {
					t.Fatal(err)
				}
				aead, err := cipher.NewGCM(block)
				if err != nil {
					t.Fatal(err)
				}
				return &Cipher{AEAD: aead}
			}(),
			key:          key32,
			expectPrefix: string(prefixCipher),
		},
		{
			name: "Cipher (XChaCha-Poly1305)",
			mode: func() Encryptor {
				aead, err := chacha20poly1305.NewX(key32)
				if err != nil {
					t.Fatal(err)
				}
				return &Cipher{AEAD: aead}
			}(),
			key:          key32,
			expectPrefix: string(prefixCipher),
		},
	}

	data := []byte("hello, secret world!")

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test Encryption
			encryptedData, err := Encrypt(tt.mode, data)
			if err != nil {
				t.Fatalf("Encrypt error: %v", err)
			}

			if len(encryptedData) < prefixLen {
				t.Fatalf("Encrypted data too short: %d", len(encryptedData))
			}

			if !bytes.HasPrefix(encryptedData, []byte(tt.expectPrefix)) {
				t.Errorf("Expected prefix %q, got %q", tt.expectPrefix, encryptedData[:prefixLen])
			}

			// Test Decryption
			decryptedData, decMode, err := Decrypt(tt.mode, encryptedData)
			if err != nil {
				t.Fatalf("Decrypt error: %v", err)
			}

			if decMode != tt.mode.Mode() {
				t.Errorf("Expected mode %v, got %v", tt.mode.Mode(), decMode)
			}

			if !bytes.Equal(decryptedData, data) {
				t.Errorf("Expected decrypted data %q, got %q", data, decryptedData)
			}
		})
	}
}

func TestDecryptionShortData(t *testing.T) {
	key32 := []byte("12345678901234567890123456789012")
	_, _, err := Decrypt(&AES_GCM{Key: key32}, []byte("sh")) // less than prefix length
	if err == nil {
		t.Error("Expected error for short ciphertext, got nil")
	}
}

func TestDecryptionUnknownMode(t *testing.T) {
	key32 := []byte("12345678901234567890123456789012")
	_, _, err := Decrypt(&AES_GCM{Key: key32}, []byte("x99somedata_with_many_chars_to_pass_len_check"))
	if err == nil {
		t.Error("Expected error for decrypting invalid data/mode, got nil")
	}
}

func TestCipherNilAEAD(t *testing.T) {
	c := &Cipher{AEAD: nil}
	_, err := c._encrypt([]byte("test data"))
	if err == nil {
		t.Error("Expected error for nil AEAD, got nil")
	}
}

func TestCipherMode(t *testing.T) {
	c := &Cipher{AEAD: nil}
	if c.Mode() != EncryptModeCipher {
		t.Errorf("Expected mode %v, got %v", EncryptModeCipher, c.Mode())
	}
}

// TestCipherWithDifferentAEADs tests Cipher with different AEAD implementations
func TestCipherWithDifferentAEADs(t *testing.T) {
	prefixCipher := getPrefix(EncryptModeCipher)

	key32 := []byte("12345678901234567890123456789012")
	data := []byte("test data for cipher")

	tests := []struct {
		name  string
		setup func() cipher.AEAD
	}{
		{
			name: "AES-GCM",
			setup: func() cipher.AEAD {
				block, err := aes.NewCipher(key32)
				if err != nil {
					t.Fatal(err)
				}
				aead, err := cipher.NewGCM(block)
				if err != nil {
					t.Fatal(err)
				}
				return aead
			},
		},
		{
			name: "XChaCha20-Poly1305",
			setup: func() cipher.AEAD {
				aead, err := chacha20poly1305.NewX(key32)
				if err != nil {
					t.Fatal(err)
				}
				return aead
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			aead := tt.setup()
			c := &Cipher{AEAD: aead}

			encrypted, err := c._encrypt(data)
			if err != nil {
				t.Fatalf("Encryption failed: %v", err)
			}

			// Verify prefix
			if !bytes.HasPrefix(encrypted, []byte(prefixCipher)) {
				t.Errorf("Expected prefix %q, got %q", prefixCipher, encrypted[:prefixLen])
			}

			// Decrypt using the generic Decrypt function
			decrypted, decMode, err := Decrypt(c, encrypted)
			if err != nil {
				t.Fatalf("Decryption failed: %v", err)
			}

			if decMode != EncryptModeCipher {
				t.Errorf("Expected mode %v, got %v", EncryptModeCipher, decMode)
			}

			if !bytes.Equal(decrypted, data) {
				t.Errorf("Expected %q, got %q", data, decrypted)
			}
		})
	}
}

// TestCipherEdgeCases tests edge cases for Cipher
func TestCipherEdgeCases(t *testing.T) {
	prefixCipher := []byte(getPrefix(EncryptModeCipher))

	key32 := []byte("12345678901234567890123456789012")
	aead, err := chacha20poly1305.NewX(key32)
	if err != nil {
		t.Fatal(err)
	}
	c := &Cipher{AEAD: aead}

	// Test empty data
	emptyData := []byte{}
	encrypted, err := c._encrypt(emptyData)
	if err != nil {
		t.Fatalf("Encryption of empty data failed: %v", err)
	}
	if !bytes.HasPrefix(encrypted, prefixCipher) {
		t.Error("Empty data encryption should have correct prefix")
	}

	// Test large data
	largeData := make([]byte, 1024*1024) // 1MB
	for i := range largeData {
		largeData[i] = byte(i % 256)
	}
	encrypted, err = c._encrypt(largeData)
	if err != nil {
		t.Fatalf("Encryption of large data failed: %v", err)
	}
	if !bytes.HasPrefix(encrypted, prefixCipher) {
		t.Error("Large data encryption should have correct prefix")
	}

	// Verify we can decrypt the large data
	decrypted, decMode, err := Decrypt(c, encrypted)
	if err != nil {
		t.Fatalf("Decryption of large data failed: %v", err)
	}
	if decMode != EncryptModeCipher {
		t.Errorf("Expected mode %v, got %v", EncryptModeCipher, decMode)
	}
	if !bytes.Equal(decrypted, largeData) {
		t.Error("Decrypted large data doesn't match original")
	}
}
