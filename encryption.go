package encrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"

	"github.com/hako/branca"
	"golang.org/x/crypto/chacha20poly1305"
)

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
	token := BytesToString(cipherData)
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
	return cipher_encrypt(aesgcm, prefixAES256GCM, data, nil)

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
	return cipher_decrypt(aesgcm, getPrefix(ag.Mode()), cipherData, nil)
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
	return cipher_encrypt(aead, prefixXChaCha, data, nil)
}

func (xcha *XChaCha_Poly1305) _decrypt(cipherData []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(xcha.Key)
	if err != nil {
		return nil, err
	}
	return cipher_decrypt(aead, getPrefix(xcha.Mode()), cipherData, nil)
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

	return cipher_encrypt(c.AEAD, prefixCipher, data, nil)
}

func (c *Cipher) _decrypt(cipherData []byte) ([]byte, error) {
	// prefixCipher := getPrefix(c.Mode())

	if c.AEAD == nil {
		return nil, fmt.Errorf("AEAD cipher not initialized")
	}
	nonceSize := c.NonceSize()
	if len(cipherData) < prefixLen+nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}
	nonce := cipherData[:nonceSize]
	ciphertext := cipherData[nonceSize:]
	return c.Open(nil, nonce, ciphertext, nil)
}
