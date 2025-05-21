package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"github.com/cloudflare/circl/sign"
	_ "github.com/cloudflare/circl/sign/eddilithium3"
	"github.com/cloudflare/circl/sign/schemes"
	"math/big"
)

// SignatureType represents the type of digital signature algorithm
type SignatureType int

const (
	// ClassicalSig (ECDSA)
	ClassicalSig SignatureType = iota
	// PostQuantumSig (Dilithium)
	PostQuantumSig
	// HybridSig (both ECDSA and Dilithium)
	HybridSig
)

// SignatureKeyPair represents a key pair for digital signatures
type SignatureKeyPair struct {
	Type       SignatureType
	ECDSAPriv  *ecdsa.PrivateKey
	ECDSAPub   *ecdsa.PublicKey
	DilithPriv sign.PrivateKey
	DilithPub  sign.PublicKey
	HybridPriv sign.PrivateKey
	HybridPub  sign.PublicKey
}

// GenerateSignatureKeyPair generates a new key pair for the specified signature type
func GenerateSignatureKeyPair(sigType SignatureType) (*SignatureKeyPair, error) {
	keyPair := &SignatureKeyPair{
		Type: sigType,
	}

	// Generate ECDSA keys for Classical
	if sigType == ClassicalSig {
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("failed to generate ECDSA key: %v", err)
		}
		keyPair.ECDSAPriv = priv
		keyPair.ECDSAPub = &priv.PublicKey
		fmt.Println("Signature private key size:", keyPair.ECDSAPriv.Curve.Params().BitSize/8)
		fmt.Println("Signature public key size: ", keyPair.ECDSAPub.Curve.Params().BitSize/8)

	}

	// Generate Dilithium keys for PostQuantum
	if sigType == PostQuantumSig {
		scheme := schemes.ByName("ML-DSA-87")
		pub, priv, err := scheme.GenerateKey()
		if err != nil {
			return nil, fmt.Errorf("failed to generate Dilithium key: %v", err)
		}
		keyPair.DilithPub = pub
		keyPair.DilithPriv = priv
		fmt.Println("Signature private key size:", scheme.PrivateKeySize())
		fmt.Println("Signature public key size: ", scheme.PublicKeySize())
	}

	if sigType == HybridSig {
		scheme := schemes.ByName("Ed448-Dilithium3")
		pub, priv, err := scheme.GenerateKey()
		if err != nil {
			return nil, fmt.Errorf("failed to generate Dilithium key: %v", err)
		}
		keyPair.HybridPub = pub
		keyPair.HybridPriv = priv
		fmt.Println("Signature private key size:", scheme.PrivateKeySize())
		fmt.Println("Signature public key size: ", scheme.PublicKeySize())
	}

	return keyPair, nil
}

// SignMessage signs a message using the private key
func SignMessage(keyPair *SignatureKeyPair, message []byte) ([]byte, error) {
	switch keyPair.Type {
	case ClassicalSig:
		hash := sha256.Sum256(message)
		r, s, err := ecdsa.Sign(rand.Reader, keyPair.ECDSAPriv, hash[:])
		if err != nil {
			return nil, fmt.Errorf("ECDSA signing failed: %v", err)
		}
		signature := append(r.Bytes(), s.Bytes()...)

		return signature, nil

	case PostQuantumSig:
		hash := sha256.Sum256(message)
		scheme := schemes.ByName("ML-DSA-87")
		signature := scheme.Sign(keyPair.DilithPriv, hash[:], nil)
		return signature, nil

	case HybridSig:
		hash := sha256.Sum256(message)
		scheme := schemes.ByName("Ed448-Dilithium3")
		signature := scheme.Sign(keyPair.HybridPriv, hash[:], nil)
		return signature, nil
	}

	return nil, fmt.Errorf("unsupported signature type")
}

// VerifySignature verifies a signature using the public key
func VerifySignature(keyPair *SignatureKeyPair, message, signature []byte) (bool, error) {
	switch keyPair.Type {
	case ClassicalSig:
		hash := sha256.Sum256(message)

		halfLen := len(signature) / 2
		r := new(big.Int).SetBytes(signature[:halfLen])
		s := new(big.Int).SetBytes(signature[halfLen:])

		return ecdsa.Verify(keyPair.ECDSAPub, hash[:], r, s), nil
	case PostQuantumSig:
		hash := sha256.Sum256(message)
		scheme := schemes.ByName("ML-DSA-87")
		return scheme.Verify(keyPair.DilithPub, hash[:], signature, nil), nil

	case HybridSig:
		hash := sha256.Sum256(message)
		scheme := schemes.ByName("Ed448-Dilithium3")
		return scheme.Verify(keyPair.HybridPub, hash[:], signature, nil), nil
	}

	return false, fmt.Errorf("unsupported signature type")
}
