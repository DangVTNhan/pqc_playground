package crypto

import (
	"bytes"
	"testing"
)

func TestDeriveKeyHKDFWithCommitment(t *testing.T) {
	// Test data
	userKey := []byte("test-encryption-key")
	salt := []byte("test-salt-value")
	info := "test-context-info"

	// Derive keys
	encKey1, commitKey1, err := DeriveKeyHKDFWithCommitment(userKey, salt, info)
	if err != nil {
		t.Fatalf("Key derivation failed: %v", err)
	}

	// Verify keys are not empty and have correct length
	if len(encKey1) != 32 {
		t.Fatalf("Encryption key length is %d, expected 32", len(encKey1))
	}
	if len(commitKey1) != 32 {
		t.Fatalf("Commitment key length is %d, expected 32", len(commitKey1))
	}

	// Derive keys again with same inputs
	encKey2, commitKey2, err := DeriveKeyHKDFWithCommitment(userKey, salt, info)
	if err != nil {
		t.Fatalf("Key derivation failed: %v", err)
	}

	// Verify keys are deterministic
	if !bytes.Equal(encKey1, encKey2) {
		t.Fatal("Derived encryption keys are not deterministic")
	}
	if !bytes.Equal(commitKey1, commitKey2) {
		t.Fatal("Derived commitment keys are not deterministic")
	}

	// Derive keys with different salt
	encKey3, commitKey3, err := DeriveKeyHKDFWithCommitment(userKey, []byte("different-salt"), info)
	if err != nil {
		t.Fatalf("Key derivation failed: %v", err)
	}

	// Verify keys are different
	if bytes.Equal(encKey1, encKey3) {
		t.Fatal("Derived encryption keys should be different with different salt")
	}
	if bytes.Equal(commitKey1, commitKey3) {
		t.Fatal("Derived commitment keys should be different with different salt")
	}
}

func TestEncryptDecryptAESGCMWithHKDF(t *testing.T) {
	// Test data
	plaintext := []byte("This is a test message for encryption and decryption with HKDF-SHA512")
	userKey := []byte("test-encryption-key-for-hkdf")
	info := "additional-context-info"

	// Encrypt with HKDF
	ciphertext, commitment, err := EncryptAESGCMWithHKDF(plaintext, userKey, info)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	// Verify ciphertext is not empty
	if len(ciphertext) == 0 {
		t.Fatal("Ciphertext is empty")
	}

	// Verify commitment is not empty
	if len(commitment) == 0 {
		t.Fatal("Commitment is empty")
	}

	// Decrypt with correct key, info, and commitment
	decrypted, err := DecryptAESGCMWithHKDF(ciphertext, userKey, info, commitment)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	// Verify decrypted text matches original
	if !bytes.Equal(plaintext, decrypted) {
		t.Fatalf("Decrypted text does not match original. Got: %s, Want: %s", decrypted, plaintext)
	}

	// Test with wrong key
	wrongKey := []byte("wrong-encryption-key")
	_, err = DecryptAESGCMWithHKDF(ciphertext, wrongKey, info, commitment)
	if err == nil {
		t.Fatal("Decryption with wrong key should fail but succeeded")
	}

	// Test with wrong info
	wrongInfo := "wrong-context-info"
	_, err = DecryptAESGCMWithHKDF(ciphertext, userKey, wrongInfo, commitment)
	if err == nil {
		t.Fatal("Decryption with wrong info should fail but succeeded")
	}

	// Test with wrong commitment
	wrongCommitment := make([]byte, len(commitment))
	copy(wrongCommitment, commitment)
	wrongCommitment[0] ^= 0x01 // Flip a bit
	_, err = DecryptAESGCMWithHKDF(ciphertext, userKey, info, wrongCommitment)
	if err == nil {
		t.Fatal("Decryption with wrong commitment should fail but succeeded")
	}
}

func TestDeriveKeyHKDF(t *testing.T) {
	// Test data
	userKey := []byte("test-encryption-key")
	salt := []byte("test-salt-value")
	info := "test-context-info"
	keyLength := 32

	// Derive key
	key1, err := DeriveKeyHKDF(userKey, salt, info, keyLength)
	if err != nil {
		t.Fatalf("Key derivation failed: %v", err)
	}

	// Verify key is not empty and has correct length
	if len(key1) != keyLength {
		t.Fatalf("Derived key length is %d, expected %d", len(key1), keyLength)
	}

	// Derive key again with same inputs
	key2, err := DeriveKeyHKDF(userKey, salt, info, keyLength)
	if err != nil {
		t.Fatalf("Key derivation failed: %v", err)
	}

	// Verify key is deterministic
	if !bytes.Equal(key1, key2) {
		t.Fatal("Derived keys are not deterministic")
	}

	// Derive key with different salt
	key3, err := DeriveKeyHKDF(userKey, []byte("different-salt"), info, keyLength)
	if err != nil {
		t.Fatalf("Key derivation failed: %v", err)
	}

	// Verify key is different
	if bytes.Equal(key1, key3) {
		t.Fatal("Derived keys should be different with different salt")
	}
	// Derive key with different info
	key4, err := DeriveKeyHKDF(userKey, salt, "different-info", keyLength)
	if err != nil {
		t.Fatalf("Key derivation failed: %v", err)
	}

	// Verify key is different
	if bytes.Equal(key1, key4) {
		t.Fatal("Derived keys should be different with different info")
	}
}
