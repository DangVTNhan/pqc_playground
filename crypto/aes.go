package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"io"
)

// DeriveKeyHKDF derives an encryption key using HKDF with SHA-512
func DeriveKeyHKDF(userKey, salt []byte, info string, keyLength int) ([]byte, error) {
	// Use HKDF with SHA-512 to derive the key
	derivedKey, err := hkdf.Key(sha512.New, userKey, salt, info, keyLength)
	if err != nil {
		return nil, fmt.Errorf("failed to derive key using HKDF: %v", err)
	}

	return derivedKey, nil
}

// DeriveKeyHKDFWithCommitment derives an encryption key and commitment using HKDF with SHA-512
func DeriveKeyHKDFWithCommitment(userKey, salt []byte, info string) (encryptionKey, commitmentKey []byte, err error) {
	// Use HKDF with SHA-512 to derive 64 bytes total (32 for encryption + 32 for commitment)
	derivedKey, err := hkdf.Key(sha512.New, userKey, salt, info, 64)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to derive key using HKDF: %v", err)
	}

	// Split the derived key into encryption key and commitment key
	encryptionKey = derivedKey[:32]
	commitmentKey = derivedKey[32:]

	return encryptionKey, commitmentKey, nil
}

// EncryptAESGCM encrypts data using AES-GCM with the provided key
// Returns the ciphertext with the nonce prepended
func EncryptAESGCM(plaintext, key []byte) ([]byte, error) {
	// Derive a 32-byte key using SHA-256 if the key is not the right size
	if len(key) != 16 && len(key) != 24 && len(key) != 32 {
		hash := sha256.Sum256(key)
		key = hash[:]
	}

	// Create a new AES cipher block
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %v", err)
	}

	// Create a new GCM mode
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %v", err)
	}

	// Create a nonce
	nonce := make([]byte, aesGCM.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %v", err)
	}

	// Encrypt the data
	ciphertext := aesGCM.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

// DecryptAESGCM decrypts data using AES-GCM with the provided key
// Expects the ciphertext to have the nonce prepended
func DecryptAESGCM(ciphertext, key []byte) ([]byte, error) {
	// Derive a 32-byte key using SHA-256 if the key is not the right size
	if len(key) != 16 && len(key) != 24 && len(key) != 32 {
		hash := sha256.Sum256(key)
		key = hash[:]
	}

	// Create a new AES cipher block
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %v", err)
	}

	// Create a new GCM mode
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %v", err)
	}

	// Check if the ciphertext is long enough
	nonceSize := aesGCM.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	// Extract the nonce and ciphertext
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]

	// Decrypt the data
	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt: %v", err)
	}

	return plaintext, nil
}

// EncryptAESGCMWithHKDF encrypts data using AES-GCM with a key derived from HKDF-SHA512
// and returns both the ciphertext and commitment
func EncryptAESGCMWithHKDF(plaintext, userKey []byte, info string) (ciphertext, commitment []byte, err error) {
	// Create a nonce
	nonce := make([]byte, 12) // GCM standard nonce size
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, fmt.Errorf("failed to generate nonce: %v", err)
	}

	// Use the nonce as salt for HKDF to derive both encryption and commitment keys
	encryptionKey, commitmentKey, err := DeriveKeyHKDFWithCommitment(userKey, nonce, info)
	if err != nil {
		return nil, nil, err
	}

	// Create a new AES cipher block
	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create AES cipher: %v", err)
	}

	// Create a new GCM mode
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create GCM: %v", err)
	}

	// Encrypt the data
	ciphertext = aesGCM.Seal(nonce, nonce, plaintext, nil)

	// Use the commitment key directly as the commitment
	commitment = commitmentKey

	return ciphertext, commitment, nil
}

// DecryptAESGCMWithHKDF decrypts data using AES-GCM with a key derived from HKDF-SHA512
// and verifies the commitment to ensure the correct key is being used
func DecryptAESGCMWithHKDF(ciphertext, userKey []byte, info string, expectedCommitment []byte) ([]byte, error) {
	// Check if the ciphertext is long enough
	if len(ciphertext) < 12 { // GCM standard nonce size
		return nil, fmt.Errorf("ciphertext too short")
	}

	// Extract the nonce and ciphertext
	nonce, encryptedData := ciphertext[:12], ciphertext[12:]

	// Use the nonce as salt for HKDF to derive both encryption and commitment keys
	encryptionKey, commitmentKey, err := DeriveKeyHKDFWithCommitment(userKey, nonce, info)
	if err != nil {
		return nil, err
	}

	// Verify commitment using the commitment key directly
	if !bytes.Equal(commitmentKey, expectedCommitment) {
		return nil, fmt.Errorf("key commitment verification failed")
	}

	// Create a new AES cipher block
	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %v", err)
	}

	// Create a new GCM mode
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %v", err)
	}

	// Decrypt the data
	plaintext, err := aesGCM.Open(nil, nonce, encryptedData, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt: %v", err)
	}

	return plaintext, nil
}
