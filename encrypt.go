package encrypt

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"runtime"
	"unsafe"

	"github.com/alexedwards/argon2id"
	"golang.org/x/crypto/bcrypt"
)

var (
	ErrInvalidCredentials = errors.New("crypto hashing: hashedPassword is not the hash of the given password")
)

// Hash computes the SHA-256 digest of the input data and returns it as a hex string.
func CheckSum(data []byte) string {
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

type Mode int

const (
	EncryptModeAESGCM           Mode = iota // Prefix: x0F (using GCM mode)
	EncryptModeXChaCha_Poly1305             // Prefix: x10
	EncryptModeBranca                       // Prefix: x11
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
		EncryptModeBranca:           "x11",

		HashModeArgon2: "h0F",
		HashModeBcrypt: "h00",
		HashModeSHA256: "h10",
	}

}

// Encrypt encrypts data based on the selected mode and prepends a 3-character identifier.
// Note: key must be exactly 32 bytes for AES-256, XChaCha20-Poly1305, and Branca.
func Encrypt(mode Encryptor, data []byte) ([]byte, error) {
	return mode._encrypt(data)
}

// Decrypt reads the 3-character identifier to determine the mode and decrypts the data.
func Decrypt(mode Encryptor, data []byte) ([]byte, Mode, error) {
	// Validate input length
	if len(data) < prefixLen {
		return nil, 0, errors.New("cipher data is too short")
	}

	plaintext, err := mode._decrypt(data)
	if err != nil {
		return nil, 0, err
	}

	return plaintext, mode.Mode(), nil
}

type Argon2Params struct {
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

var DefaultArgon2Params = &Argon2Params{
	Memory:      64 * 1024,
	Iterations:  1,
	Parallelism: uint8(runtime.NumCPU()),
	SaltLength:  16,
	KeyLength:   32,
}

type Hashable interface {
	int | *Argon2Params
}

// CreateHash creates a hash of the data using the specified hash algorithm.
// The opts parameter must be either:
//   - int: the cost factor for bcrypt (HashAlgBcrypt)
//   - *Argon2Params: the parameters for Argon2id (HashAlgArgon2)
//   - int: ignored parameter for HashAlgSHA256
func CreateHash[T Hashable](mode Mode, data []byte, opts T) ([]byte, error) {
	var ret = make([]byte, 0, 20)
	prefixValue := getPrefix(mode)

	switch mode {
	case HashModeBcrypt:
		v, bol := any(opts).(int)
		if !bol {
			return nil, errors.New("expecting an integer value for HashModeBcrypt")
		}
		b, err := bcrypt.GenerateFromPassword(data, v)
		if err != nil {
			return nil, err
		}
		ret = append(ret, []byte(prefixValue)...)
		ret = append(ret, b...)
		return ret, nil

	case HashModeArgon2:
		v, bol := any(opts).(*Argon2Params)
		if !bol {
			return nil, errors.New("expecting a pointer to Argon2Params value for HashModeArgon2")
		}
		if v == nil {
			v = DefaultArgon2Params
		}
		h, err := argon2id.CreateHash(BytesToString(data), (*argon2id.Params)(unsafe.Pointer(v)))
		if err != nil {
			return nil, err
		}
		ret = append(ret, []byte(prefixValue)...)
		ret = append(ret, []byte(h)...)
		return ret, nil

	case HashModeSHA256:
		// SHA256 does not strictly require cost/params like Bcrypt or Argon2
		hash := sha256.Sum256(data)
		ret = append(ret, []byte(prefixValue)...)
		ret = append(ret, hash[:]...)
		return ret, nil

	default:
		return nil, errors.New("unsupported hash mode")
	}
}

func CompareHash(data []byte, hashed_data []byte) error {
	if len(hashed_data) < prefixLen {
		return errors.New("hashed data too short")
	}

	switch getPrefixMode(string(hashed_data[:prefixLen])) {
	case HashModeBcrypt:
		return bcrypt.CompareHashAndPassword(hashed_data[prefixLen:], data)
	case HashModeArgon2:
		match, err := argon2id.ComparePasswordAndHash(BytesToString(data), BytesToString(hashed_data[prefixLen:]))
		if err != nil {
			return err
		}
		if !match {
			return ErrInvalidCredentials
		}
		return nil
	case HashModeSHA256:
		hash := sha256.Sum256(data)
		// Use subtle.ConstantTimeCompare to avoid timing attacks
		if subtle.ConstantTimeCompare(hash[:], hashed_data[prefixLen:]) != 1 {
			return ErrInvalidCredentials
		}
		return nil
	default:
		return errors.New("unsupported hash type")
	}
}
