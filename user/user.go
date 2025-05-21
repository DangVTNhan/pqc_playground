package user

import (
	"fmt"
	"silvertiger.com/go/client/crypto"
)

// User represents a participant in the secure communication
type User struct {
	Name             string
	KEMKeyPair       *crypto.KEMKeyPair
	SignatureKeyPair *crypto.SignatureKeyPair
}

// NewUser creates a new user with the specified name and key types
func NewUser(name string, kemType crypto.KEMType, sigType crypto.SignatureType) (*User, error) {
	// Generate KEM key pair
	kemKeyPair, err := crypto.GenerateKEMKeyPair(kemType)
	if err != nil {
		return nil, fmt.Errorf("failed to generate KEM key pair: %v", err)
	}

	// Generate signature key pair
	sigKeyPair, err := crypto.GenerateSignatureKeyPair(sigType)
	if err != nil {
		return nil, fmt.Errorf("failed to generate signature key pair: %v", err)
	}

	return &User{
		Name:             name,
		KEMKeyPair:       kemKeyPair,
		SignatureKeyPair: sigKeyPair,
	}, nil
}

// EncryptAndSign encrypts a message for the recipient and signs it
func (u *User) EncryptAndSign(recipient *User, message []byte) ([]byte, []byte, []byte, error) {
	// Encapsulate a shared secret using the recipient's public key
	sharedSecret, ciphertext, err := crypto.EncapsulateKey(recipient.KEMKeyPair)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("key encapsulation failed: %v", err)
	}

	// Encrypt the message using the shared secret
	encryptedMessage, err := crypto.EncryptAESGCM(message, sharedSecret)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("encryption failed: %v", err)
	}

	// Calculate hash

	// Sign the encrypted message
	signature, err := crypto.SignMessage(u.SignatureKeyPair, message)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("signing failed: %v", err)
	}

	return encryptedMessage, signature, ciphertext, nil
}

// DecryptAndVerify decrypts a message and verifies the signature
func (u *User) DecryptAndVerify(sender *User, encryptedMessage, signature, ciphertext []byte) ([]byte, error) {
	// Decapsulate the shared secret using the ciphertext
	sharedSecret, err := crypto.DecapsulateKey(u.KEMKeyPair, ciphertext)
	if err != nil {
		return nil, fmt.Errorf("key decapsulation failed: %v", err)
	}

	// Decrypt the message using the shared secret
	plaintext, err := crypto.DecryptAESGCM(encryptedMessage, sharedSecret)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %v", err)
	}

	// Verify the signature
	valid, err := crypto.VerifySignature(sender.SignatureKeyPair, plaintext, signature)
	if err != nil {
		return nil, fmt.Errorf("signature verification error: %v", err)
	}
	if !valid {
		return nil, fmt.Errorf("invalid signature")
	}

	return plaintext, nil
}
