package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/cloudflare/circl/sign/schemes"
)

// SerializedSignaturePublicKey represents a serialized public key for signature verification
type SerializedSignaturePublicKey struct {
	Type       SignatureType `json:"type"`
	ECDSAPub   []byte        `json:"ecdsa_pub,omitempty"`
	DilithPub  []byte        `json:"dilith_pub,omitempty"`
	HybridPub  []byte        `json:"hybrid_pub,omitempty"`
}

// SerializeSignaturePublicKey serializes a signature public key for storage or transmission
func SerializeSignaturePublicKey(keyPair *SignatureKeyPair) ([]byte, error) {
	serialized := SerializedSignaturePublicKey{
		Type: keyPair.Type,
	}

	switch keyPair.Type {
	case ClassicalSig:
		if keyPair.ECDSAPub != nil {
			serialized.ECDSAPub = ellipticPubKeyToBytes(keyPair.ECDSAPub)
		}
	case PostQuantumSig:
		if keyPair.DilithPub != nil {
			var err error
			serialized.DilithPub, err = keyPair.DilithPub.MarshalBinary()
			if err != nil {
				return nil, fmt.Errorf("failed to marshal Dilithium public key: %v", err)
			}
		}
	case HybridSig:
		if keyPair.HybridPub != nil {
			var err error
			serialized.HybridPub, err = keyPair.HybridPub.MarshalBinary()
			if err != nil {
				return nil, fmt.Errorf("failed to marshal hybrid public key: %v", err)
			}
		}
	}

	return json.Marshal(serialized)
}

// DeserializeSignaturePublicKey deserializes a signature public key from bytes
func DeserializeSignaturePublicKey(data []byte) (*SignatureKeyPair, error) {
	var serialized SerializedSignaturePublicKey
	if err := json.Unmarshal(data, &serialized); err != nil {
		return nil, fmt.Errorf("failed to unmarshal public key: %v", err)
	}

	keyPair := &SignatureKeyPair{
		Type: serialized.Type,
	}

	switch serialized.Type {
	case ClassicalSig:
		if len(serialized.ECDSAPub) > 0 {
			var err error
			keyPair.ECDSAPub, err = bytesToEllipticPubKey(serialized.ECDSAPub)
			if err != nil {
				return nil, fmt.Errorf("failed to deserialize ECDSA public key: %v", err)
			}
		}
	case PostQuantumSig:
		if len(serialized.DilithPub) > 0 {
			scheme := schemes.ByName("ML-DSA-87")
			var err error
			keyPair.DilithPub, err = scheme.UnmarshalBinaryPublicKey(serialized.DilithPub)
			if err != nil {
				return nil, fmt.Errorf("failed to deserialize Dilithium public key: %v", err)
			}
		}
	case HybridSig:
		if len(serialized.HybridPub) > 0 {
			scheme := schemes.ByName("Ed448-Dilithium3")
			var err error
			keyPair.HybridPub, err = scheme.UnmarshalBinaryPublicKey(serialized.HybridPub)
			if err != nil {
				return nil, fmt.Errorf("failed to deserialize hybrid public key: %v", err)
			}
		}
	}

	return keyPair, nil
}

// ellipticPubKeyToBytes converts an ECDSA public key to bytes
func ellipticPubKeyToBytes(pub *ecdsa.PublicKey) []byte {
	if pub == nil {
		return nil
	}

	x := pub.X.Bytes()
	y := pub.Y.Bytes()

	// Ensure both x and y are the same length by padding with zeros if needed
	keySize := (pub.Curve.Params().BitSize + 7) / 8
	result := make([]byte, 1+2*keySize)

	// Uncompressed point format
	result[0] = 4 // Uncompressed point format

	// Copy x and y with padding
	copy(result[1+keySize-len(x):1+keySize], x)
	copy(result[1+2*keySize-len(y):1+2*keySize], y)

	return result
}

// bytesToEllipticPubKey converts bytes to an ECDSA public key
func bytesToEllipticPubKey(data []byte) (*ecdsa.PublicKey, error) {
	if len(data) == 0 {
		return nil, nil
	}

	if data[0] != 4 { // Only support uncompressed point format
		return nil, fmt.Errorf("unsupported point format")
	}

	// Use P-256 curve (same as in GenerateSignatureKeyPair)
	curve := elliptic.P256()

	// Calculate key size
	keySize := (curve.Params().BitSize + 7) / 8

	if len(data) != 1+2*keySize {
		return nil, fmt.Errorf("invalid key data length")
	}

	// Extract x and y
	x := new(big.Int).SetBytes(data[1 : 1+keySize])
	y := new(big.Int).SetBytes(data[1+keySize:])

	// Create public key
	pub := &ecdsa.PublicKey{
		Curve: curve,
		X:     x,
		Y:     y,
	}

	// Verify that the point is on the curve
	if !curve.IsOnCurve(x, y) {
		return nil, fmt.Errorf("point is not on curve")
	}

	return pub, nil
}
