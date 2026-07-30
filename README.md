# **encrypt \- Go Cryptography Toolkit**

The encrypt package is a lightweight, extensible, and secure Go cryptography library providing a unified interface for multiple encryption and hashing algorithms.  
By prepending a unique 3-byte prefix to generated ciphertexts and hashes, this package enables seamless decryption and password comparison without requiring you to separately store the encryption mode or hashing algorithm in your database.

## **Key Features**

* **Unified Interface:** Standardized Encrypt(), Decrypt(), CreateHash(), and CompareHash() functions across all supported algorithms.  
* **Smart Auto-Prefixing:** Ciphertexts and hashes automatically include a 3-byte identifier (e.g., x0F for AES-GCM). The Decrypt and CompareHash functions read this prefix to automatically determine the correct algorithm.  
* **Authenticated Encryption:** Native support for modern AEAD ciphers (AES-GCM, XChaCha20-Poly1305) and Branca tokens. Branca tokens support optional TTL expirations.  
* **Custom AEAD Support:** The Cipher mode allows you to wrap any standard cipher.AEAD implementation.  
* **Secure Hashing:** Configurable password hashing using Argon2id and Bcrypt.  
* **Timing Attack Prevention:** Implements subtle.ConstantTimeCompare for safe, constant-time hash verification when using SHA-256.

## **Installation**

You can install this package using go get:

Bash  
go get github.com/pat3icki/pennychoice/pkg/encrypt

## **Supported Algorithms & Prefixes**

The package uses the following internal 3-byte prefixes to seamlessly route decryption and validation requests:

| Algorithm | Operation | Prefix | Mode Constant |
| :---- | :---- | :---- | :---- |
| **AES-256 (CFB)** | Encryption | x00 | EncryptModeAES256  |
| **AES-256-GCM** | Encryption | x0F | EncryptModeAES256GCM  |
| **XChaCha20-Poly1305** | Encryption | x10 | EncryptModeXChaCha\_Poly1305  |
| **Branca** | Encryption | x11 | EncryptModeBranca  |
| **Custom AEAD Cipher** | Encryption | hc1 | EncryptModeCipher  |
| **Bcrypt** | Hashing | h00 | HashAlgBcrypt  |
| **Argon2id** | Hashing | h0F | HashAlgArgon2  |
| **SHA-256** | Hashing | h10 | HashAlgSHA256  |

## **Usage Examples**

### **1\. Encryption & Decryption**

The package handles secure nonce and Initialization Vector (IV) generation automatically using crypto/rand.

Go  
package main

import (  
	"fmt"  
	"log"  
	"github.com/pat3icki/pennychoice/pkg/encrypt"  
)

func main() {  
	// Key must be exactly 32 bytes for AES-256, XChaCha20-Poly1305, and Branca.  
	key := \[\]byte("12345678901234567890123456789012")   
	data := \[\]byte("hello, secret world\!") //\[cite: 2\]

	// Initialize your chosen mode (e.g., AES-GCM)  
	mode := \&encrypt.AES\_GCM{Key: key} //\[cite: 2\]

	// Encrypt the data  
	ciphertext, err := encrypt.Encrypt(mode, data) //\[cite: 2\]  
	if err \!= nil {  
		log.Fatalf("Encryption failed: %v", err)  
	}

	// Decrypt (The package automatically reads the 'x0F' prefix to route the decryption)  
	plaintext, decMode, err := encrypt.Decrypt(mode, ciphertext) //\[cite: 2\]  
	if err \!= nil {  
		log.Fatalf("Decryption failed: %v", err)  
	}

	fmt.Printf("Decrypted: %s\\n", plaintext)  
	fmt.Printf("Detected Mode: %v\\n", decMode)  
}

### **2\. Password Hashing & Verification**

You can easily hash passwords using algorithms like Argon2id. The CreateHash function takes generic options (opts), which accept a pointer to Argon2Params for Argon2id, or an int cost factor for Bcrypt.

Go  
package main

import (  
	"fmt"  
	"log"  
	"github.com/pat3icki/pennychoice/pkg/encrypt"  
)

func main() {  
	password := \[\]byte("my\_super\_secure\_password") //\[cite: 3\]

	// Hash using Argon2id. Passing nil uses DefaultArgon2Params\[cite: 1, 3\].  
	hashed, err := encrypt.CreateHash(encrypt.HashAlgArgon2, password, (\*encrypt.Argon2Params)(nil)) //\[cite: 3\]  
	if err \!= nil {  
		log.Fatalf("Hashing failed: %v", err)  
	}

	// Compare password (reads the 'h0F' prefix to know it should use Argon2id)  
	err \= encrypt.CompareHash(password, hashed) //\[cite: 3\]  
	if err \!= nil {  
		if err \== encrypt.ErrInvalidCredentials { //  
			log.Fatal("Invalid password\!")  
		}  
		log.Fatal(err)  
	}  
	  
	fmt.Println("Password matched successfully\!")  
}

### **3\. Simple SHA-256 Checksum**

If you just need a quick hex-encoded SHA-256 digest, you can use the CheckSum utility\[cite: 1\]:

Go  
data := \[\]byte("hello") //\[cite: 3\]  
checksum := encrypt.CheckSum(data) //\[cite: 3\]  
// returns: "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"\[cite: 3\]

## **Security Considerations**

* **Key Length:** Always ensure encryption keys are exactly 32 bytes long for AES256, XChaCha\_Poly1305, and Branca\[cite: 1\].  
* **Ciphertext Length:** Decryption functions will return an error if the cipher data is shorter than the 3-byte prefix length\[cite: 1\].  
* **Argon2id Defaults:** The DefaultArgon2Params use 64 MiB of memory, 1 iteration, parallelism based on runtime.NumCPU(), a 16-byte salt, and a 32-byte key\[cite: 1\].
