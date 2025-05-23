package poc

import (
	"fmt"
	"log"
	"silvertiger.com/go/client/crypto"
	"silvertiger.com/go/client/user"
)

func demonstrateSecureCommunication(kemType crypto.KEMType, sigType crypto.SignatureType) {
	// Create Alice and Bob
	alice, err := user.NewUser("Alice", kemType, sigType)
	if err != nil {
		log.Fatalf("Failed to create Alice: %v", err)
	}

	bob, err := user.NewUser("Bob", kemType, sigType)
	if err != nil {
		log.Fatalf("Failed to create Bob: %v", err)
	}

	// Alice wants to send a message to Bob
	message := []byte("Hello Bob, this is a secret message from Alice!")
	fmt.Printf("Original message: %s\n", message)

	// Alice encrypts the message for Bob and signs it
	encryptedMessage, signature, ciphertext, err := alice.EncryptAndSign(bob, message)
	if err != nil {
		log.Fatalf("Encryption and signing failed: %v", err)
	}

	fmt.Printf("Encrypted message length: %d bytes\n", len(encryptedMessage))
	fmt.Printf("Signature length: %d bytes\n", len(signature))
	fmt.Printf("Ciphertext length: %d bytes\n", len(ciphertext))

	// Simulate sending the encrypted message, signature, and ciphertext to Bob
	// In a real application, these would be transmitted over a network

	// Bob decrypts the message and verifies Alice's signature
	decryptedMessage, err := bob.DecryptAndVerify(alice, encryptedMessage, signature, ciphertext)
	if err != nil {
		log.Fatalf("Decryption and verification failed: %v", err)
	}

	fmt.Printf("Decrypted message: %s\n", decryptedMessage)

	// Verify that the decrypted message matches the original
	if string(decryptedMessage) == string(message) {
		fmt.Println("Success! The message was securely transmitted and verified.")
	} else {
		fmt.Println("Error: The decrypted message does not match the original.")
	}
}

// RunCryptographyDemo demonstrates various cryptographic schemes
func RunCryptographyDemo() {
	// Create Alice and Bob with different cryptographic schemes

	// 1. Classical cryptography (ECDH + ECDSA)
	fmt.Println("=== Classical Cryptography (ECDH + ECDSA) ===")
	demonstrateSecureCommunication(crypto.Classical, crypto.ClassicalSig)

	// 2. Post-quantum cryptography (Kyber + Dilithium)
	fmt.Println("\n=== Post-Quantum Cryptography (Kyber + Dilithium) ===")
	demonstrateSecureCommunication(crypto.PostQuantum, crypto.PostQuantumSig)

	// 3. Hybrid cryptography (ECDH+Kyber + ECDSA+Dilithium)
	fmt.Println("\n=== Hybrid Cryptography (ECDH+Kyber + ECDSA+Dilithium) ===")
	demonstrateSecureCommunication(crypto.Hybrid, crypto.HybridSig)
}
