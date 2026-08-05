package encrypt

import (
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
	"unsafe"
)

func BytesToString(b []byte) string {
	return unsafe.String(unsafe.SliceData(b), len(b))
}

func StringToBytes(s string) []byte {
	return unsafe.Slice(unsafe.StringData(s), len(s))
}

func getPrefix(m Mode) string {
	// the first call into package is Write But Later is
	// Forever READ
	ret := prefixes[m]
	return ret

}

func getPrefixMode(str string) Mode {
	var ret Mode
	for mode, value := range prefixes {
		if value == str {
			ret = mode
		}
	}
	return ret
}

func cipher_encrypt(cipher cipher.AEAD, prefix string, data []byte, additionalData []byte) ([]byte, error) {
	nonceSize := cipher.NonceSize()
	// Pre-allocate the exact capacity needed to avoid allocations during Seal
	out := make([]byte, prefixLen, prefixLen+nonceSize+len(data)+cipher.Overhead())
	copy(out, prefix)

	nonce := make([]byte, nonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	// Append nonce to the output slice
	out = append(out, nonce...)
	// Seal appends the ciphertext and authentication tag to the output slice
	out = cipher.Seal(out, nonce, data, additionalData)
	return out, nil
}

func cipher_decrypt(cipher cipher.AEAD, prefix string, encrypted_data []byte, additionalData []byte) (ret []byte, err error) {
	nonceSize := cipher.NonceSize()
	if len(encrypted_data) < prefixLen+nonceSize {
		err = fmt.Errorf("ciphertext too short")
		return
	}
	nonce := encrypted_data[:nonceSize]
	ciphertext := encrypted_data[nonceSize:]
	return cipher.Open(nil, nonce, ciphertext, additionalData)
}
