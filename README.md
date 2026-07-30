## **Encrypt: Go Cryptography Toolkit**

A lightweight, extensible, and secure Go cryptography package providing a unified interface for multiple encryption and hashing algorithms.  
This package simplifies cryptographic operations by automatically handling nonces, initial value (IV) generation, and algorithm identification. By prepending a unique 3-byte prefix to generated ciphertexts and hashes, encrypt enables seamless decryption and password comparison without requiring you to store the encryption mode or hashing algorithm separately in your database.

### **Key Features**

* **Unified API:** Use standard Encrypt(), Decrypt(), CreateHash(), and CompareHash() functions across all supported algorithms.  
* **Smart Auto-Prefixing:** Ciphertexts and hashes automatically include a 3-byte identifier (e.g., x0F for AES-GCM) for automatic mode detection during decryption and comparison.  
* **Authenticated Encryption:** Native support for modern AEAD ciphers and Branca tokens with optional TTL expirations.  
* **Secure Hashing:** Configurable password hashing with Argon2id and Bcrypt, plus fast checksums via SHA-256.  
* **Timing Attack Prevention:** Implements subtle.ConstantTimeCompare for safe, constant-time hash verification.

### **Supported Algorithms**

**Encryption Modes:**

* AES-256 (CFB Mode)  
* AES-256-GCM  
* XChaCha20-Poly1305  
* Branca (Authenticated Encrypted API Tokens)  
* Custom AEAD Implementations (EncryptModeCipher)

**Hashing Algorithms:**

* Argon2id (Supports fully customizable parameters like memory, iterations, and parallelism)  
* Bcrypt (Supports configurable cost factors)  
* SHA-256

### **Prefix Identifiers Reference**

The package uses the following internal prefixes to seamlessly route decryption and validation requests:

| Algorithm | Operation | Prefix |
| :---- | :---- | :---- |
| AES-256 (CFB) | Encryption | x00 |
| AES-256-GCM | Encryption | x0F |
| XChaCha20-Poly1305 | Encryption | x10 |
| Branca | Encryption | x11 |
| Custom AEAD Cipher | Encryption | hc1 |
| Bcrypt | Hashing | h00 |
| Argon2id | Hashing | h0F |
| SHA-256 | Hashing | h10 |

### **Installation**

Bash  
go get github.com/pat3icki/pennychoice/pkg/encrypt

### **Quick Start Examples**

#### **1\. Encryption & Decryption**

Go  
package main

import (  
	"fmt"  
	"log"  
	"github.com/pat3icki/pennychoice/pkg/encrypt"  
)

func main() {  
	key := \[\]byte("12345678901234567890123456789012") // Must be 32 bytes  
	data := \[\]byte("top secret message")

	// Initialize your chosen mode  
	mode := \&encrypt.AES\_GCM{Key: key}

	// Encrypt the data  
	ciphertext, err := encrypt.Encrypt(mode, data)  
	if err \!= nil {  
		log.Fatalf("Encryption failed: %v", err)  
	}

	// Decrypt (The package automatically validates the prefix)  
	plaintext, decMode, err := encrypt.Decrypt(mode, ciphertext)  
	if err \!= nil {  
		log.Fatalf("Decryption failed: %v", err)  
	}

	fmt.Printf("Decrypted: %s\\n", plaintext)  
	fmt.Printf("Used Mode: %v\\n", decMode)  
}

#### **2\. Password Hashing & Verification**

Go  
package main

import (  
	"fmt"  
	"log"  
	"github.com/pat3icki/pennychoice/pkg/encrypt"  
)

func main() {  
	password := \[\]byte("super\_secure\_password")

	// Hash using Argon2id with default secure parameters  
	hashed, err := encrypt.CreateHash(encrypt.HashAlgArgon2, password, (\*encrypt.Argon2Params)(nil))  
	if err \!= nil {  
		log.Fatalf("Hashing failed: %v", err)  
	}

	// Compare password (reads the 'h0F' prefix to know it should use Argon2id)  
	err \= encrypt.CompareHash(password, hashed)  
	if err \!= nil {  
		if err \== encrypt.ErrInvalidCredentials {  
			log.Fatal("Invalid password\!")  
		}  
		log.Fatal(err)  
	}  
	  
	fmt.Println("Password matched successfully\!")  
}

### **Security Notes**

* Always ensure encryption keys are kept secure and are exactly 32 bytes long for AES-256, XChaCha20-Poly1305, and Branca implementations.  
* Cryptographically secure random nonces and Initialization Vectors (IVs) are automatically generated using crypto/rand under the hood during every encryption call.
