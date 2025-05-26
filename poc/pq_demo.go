package poc

import (
	"fmt"
	"log"

	"silvertiger.com/go/client/go-mls"
)

// PostQuantumMLSDemo demonstrates the usage of the new post-quantum cipher suite
func PostQuantumMLSDemo() {
	fmt.Println("=== Post-Quantum MLS Demo ===")
	fmt.Println("Using Kyber1024 for KEM and Dilithium3 for Digital Signatures")
	fmt.Println()

	// Use the new post-quantum cipher suite
	suite := mls.KYBER1024_AES256GCM_SHA512_DILITHIUM3

	fmt.Printf("Cipher Suite: %s\n", suite.String())
	fmt.Printf("Signature Scheme: %s\n", suite.Scheme().String())
	fmt.Printf("Supported: %t\n", suite.Supported())
	fmt.Println()

	// Test signature functionality
	fmt.Println("--- Testing Dilithium3 Signatures ---")
	testDilithiumSignatures(suite)
	fmt.Println()

	// Test KEM functionality
	fmt.Println("--- Testing Kyber1024 KEM ---")
	testKyberKEM(suite)
	fmt.Println()

	// Test AEAD functionality
	fmt.Println("--- Testing AES256-GCM ---")
	testAES256GCM(suite)
	fmt.Println()

	// Test hash functionality
	fmt.Println("--- Testing SHA512 ---")
	testSHA512(suite)
	fmt.Println()

	fmt.Println("Post-quantum cipher suite demo completed successfully!")
}

func testDilithiumSignatures(suite mls.CipherSuite) {
	sigScheme := suite.Scheme()

	// Generate a key pair
	fmt.Println("Generating Dilithium3 key pair...")
	keyPair, err := sigScheme.Generate()
	if err != nil {
		log.Fatalf("Failed to generate key pair: %v", err)
	}
	fmt.Printf("✓ Key pair generated (private key: %d bytes, public key: %d bytes)\n",
		len(keyPair.Data), len(keyPair.PublicKey.Data))

	// Sign a message
	message := []byte("Hello, post-quantum cryptography!")
	fmt.Printf("Signing message: %s\n", string(message))

	signature, err := sigScheme.Sign(&keyPair, message)
	if err != nil {
		log.Fatalf("Failed to sign message: %v", err)
	}
	fmt.Printf("✓ Message signed (signature: %d bytes)\n", len(signature))

	// Verify the signature
	fmt.Println("Verifying signature...")
	valid := sigScheme.Verify(&keyPair.PublicKey, message, signature)
	if !valid {
		log.Fatal("Signature verification failed!")
	}
	fmt.Println("✓ Signature verified successfully")

	// Test with wrong message
	wrongMessage := []byte("Wrong message")
	valid = sigScheme.Verify(&keyPair.PublicKey, wrongMessage, signature)
	if valid {
		log.Fatal("Signature verification should have failed!")
	}
	fmt.Println("✓ Signature correctly rejected for wrong message")
}

func testKyberKEM(suite mls.CipherSuite) {
	hpkeInstance := suite.Hpke()

	// Generate a key pair
	fmt.Println("Generating Kyber1024 key pair...")
	keyPair, err := hpkeInstance.Generate()
	if err != nil {
		log.Fatalf("Failed to generate key pair: %v", err)
	}
	fmt.Printf("✓ Key pair generated (private key: %d bytes, public key: %d bytes)\n",
		len(keyPair.Data), len(keyPair.PublicKey.Data))

	// Test encryption/decryption
	plaintext := []byte("Secret post-quantum message!")
	aad := []byte("additional authenticated data")

	fmt.Printf("Encrypting message: %s\n", string(plaintext))
	ciphertext, err := hpkeInstance.Encrypt(keyPair.PublicKey, aad, plaintext)
	if err != nil {
		log.Fatalf("Failed to encrypt: %v", err)
	}
	fmt.Printf("✓ Message encrypted (KEM output: %d bytes, ciphertext: %d bytes)\n",
		len(ciphertext.KEMOutput), len(ciphertext.Ciphertext))

	fmt.Println("Decrypting message...")
	decrypted, err := hpkeInstance.Decrypt(keyPair, aad, ciphertext)
	if err != nil {
		log.Fatalf("Failed to decrypt: %v", err)
	}

	if string(decrypted) != string(plaintext) {
		log.Fatalf("Decryption failed! Expected: %s, Got: %s", string(plaintext), string(decrypted))
	}
	fmt.Printf("✓ Message decrypted successfully: %s\n", string(decrypted))

	// Test key derivation
	fmt.Println("Testing deterministic key derivation...")
	seed := make([]byte, 64)
	for i := range seed {
		seed[i] = byte(i % 256)
	}

	derivedKey1, err := hpkeInstance.Derive(seed)
	if err != nil {
		log.Fatalf("Failed to derive key: %v", err)
	}

	derivedKey2, err := hpkeInstance.Derive(seed)
	if err != nil {
		log.Fatalf("Failed to derive key second time: %v", err)
	}

	if !derivedKey1.PublicKey.Equals(derivedKey2.PublicKey) {
		log.Fatal("Derived keys should be identical for same seed!")
	}
	fmt.Println("✓ Deterministic key derivation working correctly")
}

func testAES256GCM(suite mls.CipherSuite) {
	// Test AES256-GCM
	key := make([]byte, 32) // 256-bit key
	for i := range key {
		key[i] = byte(i)
	}

	fmt.Println("Creating AES256-GCM cipher...")
	aead, err := suite.NewAEAD(key)
	if err != nil {
		log.Fatalf("Failed to create AEAD: %v", err)
	}
	fmt.Printf("✓ AES256-GCM cipher created (key size: %d bytes)\n", len(key))

	plaintext := []byte("AES256-GCM test message")
	nonce := make([]byte, 12) // GCM nonce
	for i := range nonce {
		nonce[i] = byte(i)
	}
	aad := []byte("additional authenticated data")

	fmt.Printf("Encrypting with AES256-GCM: %s\n", string(plaintext))
	ciphertext := aead.Seal(nil, nonce, plaintext, aad)
	fmt.Printf("✓ Encrypted (ciphertext: %d bytes)\n", len(ciphertext))

	fmt.Println("Decrypting with AES256-GCM...")
	decrypted, err := aead.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		log.Fatalf("Failed to decrypt: %v", err)
	}

	if string(decrypted) != string(plaintext) {
		log.Fatalf("Decryption failed! Expected: %s, Got: %s", string(plaintext), string(decrypted))
	}
	fmt.Printf("✓ Decrypted successfully: %s\n", string(decrypted))
}

func testSHA512(suite mls.CipherSuite) {
	data := []byte("SHA512 test data")

	fmt.Printf("Hashing data with SHA512: %s\n", string(data))
	digest := suite.Digest(data)

	fmt.Printf("✓ SHA512 digest computed (%d bytes): %x...\n", len(digest), digest[:8])

	if len(digest) != 64 {
		log.Fatalf("Expected 64-byte digest, got %d bytes", len(digest))
	}
	fmt.Println("✓ SHA512 digest length correct")
}
