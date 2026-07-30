 
# encrypt - Go Cryptography Toolkit

The `encrypt` package is a lightweight, extensible, and secure Go cryptography library providing a unified interface for multiple encryption and hashing algorithms.  
By prepending a unique 3-byte prefix to generated ciphertexts and hashes, this package enables seamless decryption and password comparison without requiring you to separately store the encryption mode or hashing algorithm in your database.

## Key Features

* **Unified Interface:** Standardized `Encrypt()`, `Decrypt()`, `CreateHash()`, and `CompareHash()` functions across all supported algorithms.
* **Smart Auto-Prefixing:** Ciphertexts and hashes automatically include a 3-byte identifier (e.g., `x0F` for AES-GCM). The `Decrypt` and `CompareHash` functions read this prefix to automatically determine the correct algorithm.
* **Authenticated Encryption:** Native support for modern AEAD ciphers (AES-GCM, XChaCha20-Poly1305) and Branca tokens. Branca tokens support optional TTL expirations.
* **Custom AEAD Support:** The `Cipher` mode allows you to wrap any standard `cipher.AEAD` implementation.
* **Secure Hashing:** Configurable password hashing using Argon2id and Bcrypt.
* **Timing Attack Prevention:** Implements `subtle.ConstantTimeCompare` for safe, constant-time hash verification when using SHA-256.

## Installation

You can install this package using `go get`:

```bash
go get github.com/pat3icki/encrypt
```

## Supported Algorithms & Prefixes

The package uses the following internal 3-byte prefixes to seamlessly route decryption and validation requests:

| Algorithm | Operation | Prefix | Mode Constant |
| :---- | :---- | :---- | :---- |
| **AES-256 (CFB)** | Encryption | `x00` | `EncryptModeAES256` |
| **AES-256-GCM** | Encryption | `x0F` | `EncryptModeAES256GCM` |
| **XChaCha20-Poly1305** | Encryption | `x10` | `EncryptModeXChaCha_Poly1305` |
| **Branca** | Encryption | `x11` | `EncryptModeBranca` |
| **Custom AEAD Cipher** | Encryption | `hc1` | `EncryptModeCipher` |
| **Bcrypt** | Hashing | `h00` | `HashAlgBcrypt` |
| **Argon2id** | Hashing | `h0F` | `HashAlgArgon2` |
| **SHA-256** | Hashing | `h10` | `HashAlgSHA256` |

## Usage Examples

### 1. Encryption & Decryption

The package handles secure nonce and Initialization Vector (IV) generation automatically using `crypto/rand`.

```go
package main

import (
	"fmt"
	"log"

	"github.com/pat3icki/pennychoice/pkg/encrypt"
)

func main() {
	// Key must be exactly 32 bytes for AES-256, XChaCha20-Poly1305, and Branca.
	key := []byte("12345678901234567890123456789012")
	data := []byte("hello, secret world!")

	// Initialize your chosen mode (e.g., AES-GCM)
	mode := &encrypt.AES_GCM{Key: key}

	// Encrypt the data
	ciphertext, err := encrypt.Encrypt(mode, data)
	if err != nil {
		log.Fatalf("Encryption failed: %v", err)
	}

	// Decrypt (The package automatically reads the 'x0F' prefix to route the decryption)
	plaintext, decMode, err := encrypt.Decrypt(mode, ciphertext)
	if err != nil {
		log.Fatalf("Decryption failed: %v", err)
	}

	fmt.Printf("Decrypted: %s\n", plaintext)
	fmt.Printf("Detected Mode: %v\n", decMode)
}
```

### 2. Password Hashing & Verification

You can easily hash passwords using algorithms like Argon2id. The `CreateHash` function takes generic options (`opts`), which accept a pointer to `Argon2Params` for Argon2id, or an `int` cost factor for Bcrypt.

```go
package main

import (
	"fmt"
	"log"

	"github.com/pat3icki/pennychoice/pkg/encrypt"
)

func main() {
	password := []byte("my_super_secure_password")

	// Hash using Argon2id. Passing nil uses DefaultArgon2Params.
	hashed, err := encrypt.CreateHash(encrypt.HashAlgArgon2, password, (*encrypt.Argon2Params)(nil))
	if err != nil {
		log.Fatalf("Hashing failed: %v", err)
	}

	// Compare password (reads the 'h0F' prefix to know it should use Argon2id)
	err = encrypt.CompareHash(password, hashed)
	if err != nil {
		if err == encrypt.ErrInvalidCredentials {
			log.Fatal("Invalid password!")
		}
		log.Fatal(err)
	}

	fmt.Println("Password matched successfully!")
}
```

### 3. Simple SHA-256 Checksum

If you just need a quick hex-encoded SHA-256 digest, you can use the `CheckSum` utility:

```go
data := []byte("hello")
checksum := encrypt.CheckSum(data)
// returns: "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
```

## API Reference

### Encryption Types

```go
type Encryptor interface {
    Mode() Mode
    _encrypt(data []byte) ([]byte, error)
    _decrypt(cipher []byte) ([]byte, error)
}
```

| Type | Fields | Description |
|------|--------|-------------|
| `AES256` | `Key []byte` | AES-256-CFB encryption |
| `AES_GCM` | `Key []byte` | AES-256-GCM authenticated encryption |
| `XChaCha_Poly1305` | `Key []byte` | XChaCha20-Poly1305 authenticated encryption |
| `Branca` | `Password string`, `Expire uint32` | Branca token encoding with optional TTL |
| `Cipher` | `cipher.AEAD` | Generic wrapper for any `cipher.AEAD` implementation |

### Encryption Functions

| Function | Signature | Description |
|----------|-----------|-------------|
| `Encrypt` | `Encrypt(mode Encryptor, data []byte) ([]byte, error)` | Encrypts data and prepends the mode prefix |
| `Decrypt` | `Decrypt(mode Encryptor, data []byte) ([]byte, Mode, error)` | Reads the prefix and decrypts the ciphertext |
| `CheckSum` | `CheckSum(data []byte) string` | Returns a hex-encoded SHA-256 digest |

### Hashing Types

```go
type HashType int

const (
    HashAlgBcrypt HashType = iota
    HashAlgArgon2
    HashAlgSHA256
)

type Argon2Params struct {
    Memory      uint32 // The amount of memory used by the algorithm (in kibibytes)
    Iterations  uint32 // The number of iterations over the memory
    Parallelism uint8  // The number of threads (or lanes) used by the algorithm
    SaltLength  uint32 // Length of the random salt
    KeyLength   uint32 // Length of the generated key
}
```

### Hashing Functions

| Function | Signature | Description |
|----------|-----------|-------------|
| `CreateHash` | `CreateHash[T Hashable](mode HashType, data []byte, opts T) ([]byte, error)` | Creates a prefixed hash using the specified algorithm |
| `CompareHash` | `CompareHash(data []byte, hashed_data []byte) error` | Verifies data against a prefixed hash |

### Generic Constraints

The `CreateHash` function accepts the following generic types via the `Hashable` constraint (`int | *Argon2Params`):

| Algorithm | `opts` Type | Description |
|-----------|-------------|-------------|
| `HashAlgBcrypt` | `int` | The cost factor (e.g., 10-14) |
| `HashAlgArgon2` | `*Argon2Params` | Argon2id parameters (pass `nil` for defaults) |
| `HashAlgSHA256` | `int` | Ignored placeholder |

### Default Argon2id Parameters

```go
var DefaultArgon2Params = &Argon2Params{
    Memory:      64 * 1024,          // 64 MiB
    Iterations:  1,
    Parallelism: uint8(runtime.NumCPU()),
    SaltLength:  16,
    KeyLength:   32,
}
```

## Security Considerations

* **Key Length:** Always ensure encryption keys are exactly 32 bytes long for `AES256`, `XChaCha_Poly1305`, and `Branca`.
* **Ciphertext Length:** Decryption functions will return an error if the cipher data is shorter than the 3-byte prefix length.
* **Argon2id Defaults:** The `DefaultArgon2Params` use 64 MiB of memory, 1 iteration, parallelism based on `runtime.NumCPU()`, a 16-byte salt, and a 32-byte key.
* **Constant-Time Comparison:** SHA-256 hash verification uses `subtle.ConstantTimeCompare` to mitigate timing attacks.
* **Random Nonce/IV Generation:** All AEAD modes and CFB automatically generate secure random nonces and IVs using `crypto/rand`.
```
