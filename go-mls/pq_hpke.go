package mls

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"

	"github.com/cloudflare/circl/kem"
	"github.com/cloudflare/circl/kem/schemes"
	"golang.org/x/crypto/hkdf"
)

// PostQuantumHPKE provides HPKE-like functionality for post-quantum KEMs
type PostQuantumHPKE struct {
	kemScheme kem.Scheme
}

// NewKyber1024HPKE creates a new post-quantum HPKE instance using Kyber1024
func NewKyber1024HPKE() *PostQuantumHPKE {
	scheme := schemes.ByName("Kyber1024")
	if scheme == nil {
		panic("Kyber1024 scheme not available")
	}
	return &PostQuantumHPKE{kemScheme: scheme}
}

// Generate generates a new Kyber key pair
func (pq *PostQuantumHPKE) Generate() (HPKEPrivateKey, error) {
	pub, priv, err := pq.kemScheme.GenerateKeyPair()
	if err != nil {
		return HPKEPrivateKey{}, err
	}

	privBytes, err := priv.MarshalBinary()
	if err != nil {
		return HPKEPrivateKey{}, err
	}

	pubBytes, err := pub.MarshalBinary()
	if err != nil {
		return HPKEPrivateKey{}, err
	}

	key := HPKEPrivateKey{
		Data:      privBytes,
		PublicKey: HPKEPublicKey{pubBytes},
	}
	return key, nil
}

// Derive derives a Kyber key pair from a seed
func (pq *PostQuantumHPKE) Derive(seed []byte) (HPKEPrivateKey, error) {
	if len(seed) < pq.kemScheme.SeedSize() {
		return HPKEPrivateKey{}, fmt.Errorf("seed too short: need %d bytes, got %d", pq.kemScheme.SeedSize(), len(seed))
	}

	pub, priv := pq.kemScheme.DeriveKeyPair(seed[:pq.kemScheme.SeedSize()])

	privBytes, err := priv.MarshalBinary()
	if err != nil {
		return HPKEPrivateKey{}, err
	}

	pubBytes, err := pub.MarshalBinary()
	if err != nil {
		return HPKEPrivateKey{}, err
	}

	key := HPKEPrivateKey{
		Data:      privBytes,
		PublicKey: HPKEPublicKey{pubBytes},
	}
	return key, nil
}

// Encrypt performs KEM encapsulation and returns the encapsulated key and ciphertext
func (pq *PostQuantumHPKE) Encrypt(pub HPKEPublicKey, aad, pt []byte) (HPKECiphertext, error) {
	// Unmarshal the public key
	pubKey, err := pq.kemScheme.UnmarshalBinaryPublicKey(pub.Data)
	if err != nil {
		return HPKECiphertext{}, err
	}

	// Perform KEM encapsulation to get shared secret
	kemOutput, sharedSecret, err := pq.kemScheme.Encapsulate(pubKey)
	if err != nil {
		return HPKECiphertext{}, err
	}

	// Derive encryption key from shared secret using HKDF
	encKey := make([]byte, 32) // AES-256 key
	hkdf := hkdf.New(sha256.New, sharedSecret, nil, []byte("pq-hpke-enc"))
	_, err = io.ReadFull(hkdf, encKey)
	if err != nil {
		return HPKECiphertext{}, err
	}

	// Create AES-GCM cipher
	block, err := aes.NewCipher(encKey)
	if err != nil {
		return HPKECiphertext{}, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return HPKECiphertext{}, err
	}

	// Generate random nonce
	nonce := make([]byte, gcm.NonceSize())
	_, err = rand.Read(nonce)
	if err != nil {
		return HPKECiphertext{}, err
	}

	// Encrypt with AES-GCM
	ciphertext := gcm.Seal(nil, nonce, pt, aad)

	// Prepend nonce to ciphertext
	finalCiphertext := append(nonce, ciphertext...)

	return HPKECiphertext{
		KEMOutput:  kemOutput,
		Ciphertext: finalCiphertext,
	}, nil
}

// Decrypt performs KEM decapsulation and decrypts the ciphertext
func (pq *PostQuantumHPKE) Decrypt(priv HPKEPrivateKey, aad []byte, ct HPKECiphertext) ([]byte, error) {
	// Unmarshal the private key
	privKey, err := pq.kemScheme.UnmarshalBinaryPrivateKey(priv.Data)
	if err != nil {
		return nil, err
	}

	// Perform KEM decapsulation to get shared secret
	sharedSecret, err := pq.kemScheme.Decapsulate(privKey, ct.KEMOutput)
	if err != nil {
		return nil, err
	}

	// Derive encryption key from shared secret using HKDF (same as encryption)
	encKey := make([]byte, 32) // AES-256 key
	hkdf := hkdf.New(sha256.New, sharedSecret, nil, []byte("pq-hpke-enc"))
	_, err = io.ReadFull(hkdf, encKey)
	if err != nil {
		return nil, err
	}

	// Create AES-GCM cipher
	block, err := aes.NewCipher(encKey)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// Extract nonce and ciphertext
	if len(ct.Ciphertext) < gcm.NonceSize() {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce := ct.Ciphertext[:gcm.NonceSize()]
	ciphertext := ct.Ciphertext[gcm.NonceSize():]

	// Decrypt with AES-GCM
	plaintext, err := gcm.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// PostQuantumHPKEInstance wraps the post-quantum HPKE for use in MLS
type PostQuantumHPKEInstance struct {
	BaseSuite CipherSuite
	PQ        *PostQuantumHPKE
}

// Generate generates a new key pair using the post-quantum KEM
func (h PostQuantumHPKEInstance) Generate() (HPKEPrivateKey, error) {
	return h.PQ.Generate()
}

// Derive derives a key pair from a seed using the post-quantum KEM
func (h PostQuantumHPKEInstance) Derive(seed []byte) (HPKEPrivateKey, error) {
	return h.PQ.Derive(seed)
}

// Encrypt encrypts using the post-quantum KEM
func (h PostQuantumHPKEInstance) Encrypt(pub HPKEPublicKey, aad, pt []byte) (HPKECiphertext, error) {
	return h.PQ.Encrypt(pub, aad, pt)
}

// Decrypt decrypts using the post-quantum KEM
func (h PostQuantumHPKEInstance) Decrypt(priv HPKEPrivateKey, aad []byte, ct HPKECiphertext) ([]byte, error) {
	return h.PQ.Decrypt(priv, aad, ct)
}
