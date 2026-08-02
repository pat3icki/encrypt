package encrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"

	"github.com/hako/branca"
	"golang.org/x/crypto/chacha20poly1305"
)

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

type Encryptor interface {
	Mode() Mode
	Prefix() string
	_encrypt(data []byte) ([]byte, error)
	_decrypt(cipher []byte) ([]byte, error)
}

type Branca struct {
	Password string
	Expire   uint32
}

func (b *Branca) Mode() Mode {
	return EncryptModeBranca
}
func (b *Branca) Prefix() string {
	return getPrefix(b.Mode())
}

func (b *Branca) _encrypt(data []byte) ([]byte, error) {
	prefixBranca := getPrefix(b.Mode())

	branca := branca.NewBranca(b.Password)
	if b.Expire > 0 {
		branca.SetTTL(b.Expire)
	}
	token, err := branca.EncodeToString(string(data))
	if err != nil {
		return nil, fmt.Errorf("encode: %w", err)
	}
	// Pre-allocate and build output
	out := make([]byte, prefixLen+len(token))
	copy(out[:prefixLen], prefixBranca)
	copy(out[prefixLen:], token)
	return out, nil
}
func (b *Branca) _decrypt(cipherData []byte) ([]byte, error) {
	if len(cipherData) < prefixLen {
		return nil, fmt.Errorf("ciphertext too short")
	}
	br := branca.NewBranca(b.Password)
	if b.Expire > 0 {
		br.SetTTL(b.Expire)
	}
	token := string(cipherData[prefixLen:])
	plaintext, err := br.DecodeToString(token)
	if err != nil {
		return nil, err
	}
	return []byte(plaintext), nil
}

type AES_GCM struct {
	Key []byte
}

func (*AES_GCM) Mode() Mode {
	return EncryptModeAESGCM
}

func (ag *AES_GCM) Prefix() string {
	return getPrefix(ag.Mode())
}

func (ag *AES_GCM) _encrypt(data []byte) ([]byte, error) {
	prefixAES256GCM := getPrefix(ag.Mode())

	block, err := aes.NewCipher(ag.Key)
	if err != nil {
		return nil, err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := aesgcm.NonceSize()
	// Pre-allocate the exact capacity needed to avoid allocations during Seal
	out := make([]byte, prefixLen, prefixLen+nonceSize+len(data)+aesgcm.Overhead())
	copy(out, prefixAES256GCM)

	nonce := make([]byte, nonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	// Append nonce to the output slice
	out = append(out, nonce...)
	// Seal appends the ciphertext and authentication tag to the output slice
	out = aesgcm.Seal(out, nonce, data, nil)
	return out, nil
}

func (ag *AES_GCM) _decrypt(cipherData []byte) ([]byte, error) {
	block, err := aes.NewCipher(ag.Key)
	if err != nil {
		return nil, err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := aesgcm.NonceSize()
	if len(cipherData) < prefixLen+nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}
	nonce := cipherData[prefixLen : prefixLen+nonceSize]
	ciphertext := cipherData[prefixLen+nonceSize:]
	return aesgcm.Open(nil, nonce, ciphertext, nil)
}

type XChaCha_Poly1305 struct {
	Key []byte
}

func (*XChaCha_Poly1305) Mode() Mode {
	return EncryptModeXChaCha_Poly1305
}

func (xcha *XChaCha_Poly1305) Prefix() string {
	return getPrefix(xcha.Mode())
}

func (xcha *XChaCha_Poly1305) _encrypt(data []byte) ([]byte, error) {
	prefixXChaCha := getPrefix(xcha.Mode())

	aead, err := chacha20poly1305.NewX(xcha.Key)
	if err != nil {
		return nil, err
	}

	nonceSize := aead.NonceSize() // 24 bytes for XChaCha20
	out := make([]byte, prefixLen, prefixLen+nonceSize+len(data)+aead.Overhead())
	copy(out, prefixXChaCha)

	nonce := make([]byte, nonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	out = append(out, nonce...)
	out = aead.Seal(out, nonce, data, nil)
	return out, nil
}

func (xcha *XChaCha_Poly1305) _decrypt(cipherData []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(xcha.Key)
	if err != nil {
		return nil, err
	}
	nonceSize := aead.NonceSize()
	if len(cipherData) < prefixLen+nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}
	nonce := cipherData[prefixLen : prefixLen+nonceSize]
	ciphertext := cipherData[prefixLen+nonceSize:]
	return aead.Open(nil, nonce, ciphertext, nil)
}

type Cipher struct {
	cipher.AEAD
}

func (c *Cipher) Mode() Mode {
	return EncryptModeCipher
}

func (c *Cipher) Prefix() string {
	return getPrefix(c.Mode())
}

func (c *Cipher) _encrypt(data []byte) ([]byte, error) {
	prefixCipher := getPrefix(c.Mode())

	if c.AEAD == nil {
		return nil, fmt.Errorf("AEAD cipher not initialized")
	}

	nonceSize := c.NonceSize()
	overhead := c.Overhead()

	// Pre-allocate the final output buffer with exact capacity
	out := make([]byte, prefixLen, prefixLen+nonceSize+len(data)+overhead)
	copy(out[:prefixLen], prefixCipher)

	// Create a separate nonce slice
	nonce := make([]byte, nonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	// Append nonce to the output
	out = append(out, nonce...)

	// Seal appends the ciphertext and authentication tag to the output slice
	// The nonce parameter is the nonce we just appended
	out = c.Seal(out, nonce, data, nil)

	return out, nil
}

func (c *Cipher) _decrypt(cipherData []byte) ([]byte, error) {
	if c.AEAD == nil {
		return nil, fmt.Errorf("AEAD cipher not initialized")
	}
	nonceSize := c.NonceSize()
	if len(cipherData) < prefixLen+nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}
	nonce := cipherData[prefixLen : prefixLen+nonceSize]
	ciphertext := cipherData[prefixLen+nonceSize:]
	return c.Open(nil, nonce, ciphertext, nil)
}
