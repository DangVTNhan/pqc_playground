package crypto

import (
	"crypto/ecdh"
	"crypto/rand"
	"fmt"
	"github.com/cloudflare/circl/kem"
	"github.com/cloudflare/circl/kem/schemes"
)

// KEMType represents the type of Key Encapsulation Mechanism
type KEMType int

const (
	// Classical KEM (ECDH)
	Classical KEMType = iota
	// PostQuantum KEM (Kyber)
	PostQuantum
	// Hybrid KEM (both ECDH and Kyber)
	Hybrid
)

// KEMKeyPair represents a key pair for key encapsulation mechanisms
type KEMKeyPair struct {
	Type       KEMType
	ECDHPriv   *ecdh.PrivateKey
	ECDHPub    *ecdh.PublicKey
	KyberPriv  kem.PrivateKey
	KyberPub   kem.PublicKey
	HybridPub  kem.PublicKey
	HybridPriv kem.PrivateKey
}

// GenerateKEMKeyPair generates a new key pair for the specified KEM type
func GenerateKEMKeyPair(kemType KEMType) (*KEMKeyPair, error) {
	keyPair := &KEMKeyPair{
		Type: kemType,
	}

	// Generate ECDH keys for Classical or Hybrid
	if kemType == Classical {
		curve := ecdh.P256()
		priv, err := curve.GenerateKey(rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("failed to generate ECDH key: %v", err)
		}
		keyPair.ECDHPriv = priv
		keyPair.ECDHPub = priv.PublicKey()

		fmt.Println("KEM private key size: ", len(priv.Bytes()))
		fmt.Println("KEM public key size: ", len(keyPair.ECDHPub.Bytes()))
	}

	// Generate Kyber keys for PostQuantum or Hybrid
	if kemType == PostQuantum {
		scheme := schemes.ByName("Kyber1024")
		pub, priv, err := scheme.GenerateKeyPair()
		if err != nil {
			return nil, fmt.Errorf("failed to generate Kyber key: %v", err)
		}
		keyPair.KyberPub = pub
		keyPair.KyberPriv = priv
		fmt.Println("KEM private key size: ", scheme.PrivateKeySize())
		fmt.Println("KEM public key size: ", scheme.PublicKeySize())
	}

	if kemType == Hybrid {
		scheme := schemes.ByName("Kyber1024-X448")
		pub, priv, err := scheme.GenerateKeyPair()
		if err != nil {
			return nil, fmt.Errorf("failed to generate Kyber key: %v", err)
		}
		keyPair.HybridPub = pub
		keyPair.HybridPriv = priv
		fmt.Println("KEM private key size: ", scheme.PrivateKeySize())
		fmt.Println("KEM public key size: ", scheme.PublicKeySize())
	}

	return keyPair, nil
}

// EncapsulateKey encapsulates a shared secret using the recipient's public key
func EncapsulateKey(recipientKey *KEMKeyPair) (sharedSecret []byte, ciphertext []byte, err error) {
	switch recipientKey.Type {
	case Classical:
		// ECDH encapsulation
		secret, err := ecdh.P256().GenerateKey(rand.Reader)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to generate ECDH ephemeral key: %v", err)
		}
		ciphertext = secret.PublicKey().Bytes()
		sharedSecret, err = secret.ECDH(recipientKey.ECDHPub)
		if err != nil {
			return nil, nil, fmt.Errorf("ECDH key exchange failed: %v", err)
		}
	case PostQuantum:
		scheme := schemes.ByName("Kyber1024")
		ciphertext, sharedSecret, err = scheme.Encapsulate(recipientKey.KyberPub)
		if err != nil {
			return nil, nil, fmt.Errorf("Kyber encapsulation failed: %v", err)
		}
		fmt.Println("Shared secret: ", sharedSecret)
		if len(ciphertext) != scheme.CiphertextSize() {
			return nil, nil, fmt.Errorf("ciphertext is %d bytes, expected %d", len(ciphertext), scheme.CiphertextSize())
		}
	case Hybrid:
		scheme := schemes.ByName("Kyber1024-X448")
		ciphertext, sharedSecret, err = scheme.Encapsulate(recipientKey.HybridPub)
		if err != nil {
			return nil, nil, fmt.Errorf("Kyber encapsulation failed: %v", err)
		}
	}

	return sharedSecret, ciphertext, nil
}

// DecapsulateKey decapsulates a shared secret using the recipient's private key and the ciphertext
func DecapsulateKey(recipientKey *KEMKeyPair, ciphertext []byte) ([]byte, error) {
	switch recipientKey.Type {
	case Classical:
		curve := ecdh.P256()
		ephemeralPubKey, err := curve.NewPublicKey(ciphertext)
		if err != nil {
			return nil, fmt.Errorf("failed to parse ECDH public key: %v", err)
		}
		sharedSecret, err := recipientKey.ECDHPriv.ECDH(ephemeralPubKey)
		if err != nil {
			return nil, fmt.Errorf("ECDH key exchange failed: %v", err)
		}

		return sharedSecret, nil

	case PostQuantum:
		scheme := schemes.ByName("Kyber1024")
		sharedSecret, err := scheme.Decapsulate(recipientKey.KyberPriv, ciphertext)
		fmt.Println("Shared secret: ", sharedSecret)

		if err != nil {
			return nil, fmt.Errorf("Kyber decapsulation failed: %v", err)
		}
		return sharedSecret, nil

	case Hybrid:
		scheme := schemes.ByName("Kyber1024-X448")
		sharedSecret, err := scheme.Decapsulate(recipientKey.HybridPriv, ciphertext)
		if err != nil {
			return nil, fmt.Errorf("Hybrid decapsulation failed: %v", err)
		}
		return sharedSecret, nil
	}

	return nil, fmt.Errorf("unsupported KEM type")
}
