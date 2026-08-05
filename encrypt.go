package encrypt

import (
	"errors"
	"fmt"
	"runtime"
)

var (
	ErrInvalidCredentials = errors.New("crypto hashing: hashedPassword is not the hash of the given password")
)

type Encryptor interface {
	Mode() Mode
	Prefix() string
	_encrypt(data []byte) ([]byte, error)
	_decrypt(cipher []byte) ([]byte, error)
}

type Mode int

const (
	NoneMode                    Mode = iota
	EncryptModeAESGCM                // Prefix: x0F (using GCM mode)
	EncryptModeXChaCha_Poly1305      // Prefix: x10
	EncryptModeBranca                // Prefix: x11
	EncryptModeCipher

	HashModeBcrypt
	HashModeArgon2
	HashModeSHA256
)

const prefixLen = 3

var prefixes map[Mode]string

func init() {
	prefixes = map[Mode]string{
		EncryptModeAESGCM:           "x0F",
		EncryptModeXChaCha_Poly1305: "x10",
		EncryptModeBranca:           "x13",
		EncryptModeCipher:           "hc1",

		HashModeArgon2: "h0F",
		HashModeBcrypt: "h0X",
		HashModeSHA256: "h10",
	}

}

// Encrypt encrypts data based on the selected mode and prepends a 3-character identifier.
func Encrypt(mode Encryptor, data []byte) ([]byte, error) {
	return mode._encrypt(data)
}

// Decrypt reads the 3-character identifier to determine the mode and decrypts the data.
func Decrypt(mode Encryptor, data []byte) ([]byte, Mode, error) {
	// Validate input length
	if len(data) < prefixLen {
		return nil, 0, errors.New("cipher data is too short")
	}
	if getPrefix(mode.Mode()) != string(data[:prefixLen]) {
		// fmt.Println(string(data[:prefixLen]))
		return nil, NoneMode, fmt.Errorf("invaild encryptor: %s", data[:prefixLen])
	}

	plaintext, err := mode._decrypt(data[prefixLen:])
	if err != nil {
		return nil, 0, err
	}

	return plaintext, mode.Mode(), nil
}

type Argon2 struct {
	// The amount of memory used by the algorithm (in kibibytes).
	Memory uint32

	// The number of iterations over the memory.
	Iterations uint32

	// The number of threads (or lanes) used by the algorithm.
	// Recommended value is between 1 and runtime.NumCPU().
	Parallelism uint8

	// Length of the random salt. 16 bytes is recommended for password hashing.
	SaltLength uint32

	// Length of the generated key. 16 bytes or more is recommended.
	KeyLength uint32
}

var DefaultArgon2Params = Argon2{
	Memory:      64 * 1024,
	Iterations:  1,
	Parallelism: uint8(runtime.NumCPU()),
	SaltLength:  16,
	KeyLength:   32,
}

// CreateHash creates a hash of the data using the specified hash algorithm.
func CreateHash(hasher Hasher, data []byte) ([]byte, error) {
	return hasher._hash(data)
}

// TODO: UPDATE
func CompareHash(data []byte, hashed_data []byte) error {
	if len(hashed_data) < prefixLen {
		return errors.New("hashed data too short")
	}

	switch getPrefixMode(string(hashed_data[:prefixLen])) {
	case HashModeBcrypt:
		return (Bcrypt{})._compare(data, hashed_data)
	case HashModeArgon2:
		return (Argon2{})._compare(data, hashed_data)
	default:
		return errors.New("unsupported hash type")
	}
}
