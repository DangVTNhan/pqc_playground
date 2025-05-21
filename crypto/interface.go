package crypto

type Signer interface {
	Sign(data []byte, privateKey []byte) ([]byte, error)
	Verify(data []byte, signature []byte, publicKey []byte) (bool, error)
	GenerateKeys() (publicKey []byte, privateKey []byte, err error)
	AlgorithmName() string
}

type Encryptor interface {
	Encrypt(plaintext []byte, key []byte) ([]byte, error)
	Decrypt(ciphertext []byte, key []byte) ([]byte, error)
	GenerateKey() ([]byte, error) // For symmetric keys
	AlgorithmName() string
}

type AsymmetricEncryptor interface {
	Encrypt(plaintext []byte, publicKey []byte) ([]byte, error)
	Decrypt(ciphertext []byte, privateKey []byte) ([]byte, error)
	GenerateKeys() (publicKey []byte, privateKey []byte, err error)
	AlgorithmName() string
}
