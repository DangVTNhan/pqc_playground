package poc

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"

	"silvertiger.com/go/client/crypto"
	"silvertiger.com/go/client/user"
)

// FileChunk represents a chunk of an encrypted file
type FileChunk struct {
	Index      uint32 // Index of the chunk
	Data       []byte // Encrypted data
	Signature  []byte // Signature of the original data
	Commitment []byte // Key commitment for this chunk
}

// FileMetadata contains information about the encrypted file
type FileMetadata struct {
	OriginalName    string // Original filename
	TotalChunks     uint32 // Total number of chunks
	TotalSize       int64  // Total size of the original file
	ChunkSize       uint32 // Size of each chunk (except possibly the last one)
	EncryptionType  string // Type of encryption used
	SignerPublicKey []byte // Public key of the signer for verification
	MasterKey       []byte // Master key used for HKDF key derivation
}

const (
	// ChunkSize is the maximum size of each file chunk (1MB)
	ChunkSize = 1024 * 1024
)

// RunFileEncryptionDemo demonstrates post-quantum file encryption
func RunFileEncryptionDemo() {
	// 4. Use post-quantum cryptography to encrypt file
	fmt.Println("\n=== Post-Quantum File Encryption ===")
	filename := "PDN_FinReportQ12025.pdf"
	encryptedPath, err := EncryptFile(filename)
	if err != nil {
		log.Fatalf("File encryption failed: %v", err)
	}
	fmt.Printf("File encrypted successfully. Encrypted file saved to: %s\n", encryptedPath)

	// Decrypt the file
	decryptedPath, err := DecryptFile(encryptedPath)
	if err != nil {
		log.Fatalf("File decryption failed: %v", err)
	}
	fmt.Printf("File decrypted successfully. Decrypted file saved to: %s\n", decryptedPath)
}

// EncryptFile encrypts a file using post-quantum cryptography
// The file is split into chunks of 1MB each, and each chunk is encrypted separately
// Returns the path to the metadata file
func EncryptFile(filename string) (string, error) {
	// Create a user for encryption with a fixed seed for reproducibility
	// This ensures we can recreate the same keys for decryption
	encryptionUser, err := user.NewUser("FileEncryptor", crypto.PostQuantum, crypto.PostQuantumSig)
	if err != nil {
		return "", fmt.Errorf("failed to create user for file encryption: %v", err)
	}

	// Save the public key for verification during decryption
	pubKeyBytes, err := crypto.SerializeSignaturePublicKey(encryptionUser.SignatureKeyPair)
	if err != nil {
		return "", fmt.Errorf("failed to serialize public key: %v", err)
	}

	// Open the input file
	file, err := os.Open(filename)
	if err != nil {
		return "", fmt.Errorf("failed to open file: %v", err)
	}
	defer file.Close()

	// Get file info
	fileInfo, err := file.Stat()
	if err != nil {
		return "", fmt.Errorf("failed to get file info: %v", err)
	}

	// Create output directory if it doesn't exist
	outDir := "out"
	if err := os.MkdirAll(outDir, 0755); err != nil {
		return "", fmt.Errorf("failed to create output directory: %v", err)
	}

	// Calculate total chunks
	totalChunks := uint32((fileInfo.Size() + int64(ChunkSize) - 1) / int64(ChunkSize))

	// Generate a master user key for the file (derived from user's key material)
	// In a real application, this would be derived from the user's actual key
	masterKey := make([]byte, 32)
	if _, err := rand.Read(masterKey); err != nil {
		return "", fmt.Errorf("failed to generate master key: %v", err)
	}

	// Create metadata
	metadata := FileMetadata{
		OriginalName:    filepath.Base(filename),
		TotalSize:       fileInfo.Size(),
		ChunkSize:       ChunkSize,
		EncryptionType:  "PostQuantumWithHKDF",
		TotalChunks:     totalChunks,
		SignerPublicKey: pubKeyBytes,
		MasterKey:       masterKey,
	}

	// Create metadata file path
	metadataFilePath := filepath.Join(outDir, filepath.Base(filename)+".metadata")
	metadataFile, err := os.Create(metadataFilePath)
	if err != nil {
		return "", fmt.Errorf("failed to create metadata file: %v", err)
	}
	defer metadataFile.Close()

	// Process file in chunks
	buffer := make([]byte, ChunkSize)

	for chunkIndex := uint32(0); chunkIndex < totalChunks; chunkIndex++ {
		// Read a chunk
		bytesRead, err := file.Read(buffer)
		if err != nil && err != io.EOF {
			return "", fmt.Errorf("failed to read chunk %d: %v", chunkIndex, err)
		}

		// Create a chunk with actual data
		chunkData := buffer[:bytesRead]

		// Sign the chunk data
		signature, err := crypto.SignMessage(encryptionUser.SignatureKeyPair, chunkData)
		if err != nil {
			return "", fmt.Errorf("failed to sign chunk %d: %v", chunkIndex, err)
		}

		// Create context info for this chunk using filename and chunk index
		contextInfo := fmt.Sprintf("file:%s:chunk:%d", metadata.OriginalName, chunkIndex)

		// Encrypt the chunk data using HKDF with key commitment
		encryptedData, commitment, err := crypto.EncryptAESGCMWithHKDF(chunkData, masterKey, contextInfo)
		if err != nil {
			return "", fmt.Errorf("failed to encrypt chunk %d: %v", chunkIndex, err)
		}

		// Create a chunk
		chunk := FileChunk{
			Index:      chunkIndex,
			Data:       encryptedData,
			Signature:  signature,
			Commitment: commitment,
		}

		// Create chunk file path - one file per chunk
		chunkFilePath := filepath.Join(outDir, fmt.Sprintf("%s.chunk.%d", filepath.Base(filename), chunkIndex))
		chunkFile, err := os.Create(chunkFilePath)
		if err != nil {
			return "", fmt.Errorf("failed to create chunk file %d: %v", chunkIndex, err)
		}

		// Serialize the chunk
		chunkBytes, err := json.Marshal(chunk)
		if err != nil {
			chunkFile.Close()
			return "", fmt.Errorf("failed to marshal chunk %d: %v", chunkIndex, err)
		}

		// Write chunk to file
		if _, err := chunkFile.Write(chunkBytes); err != nil {
			chunkFile.Close()
			return "", fmt.Errorf("failed to write chunk %d: %v", chunkIndex, err)
		}

		chunkFile.Close()
		fmt.Printf("Wrote chunk %d to file %s\n", chunkIndex, chunkFilePath)
		fmt.Printf("Processed chunk %d/%d\n", chunkIndex+1, totalChunks)
	}

	// Write metadata to file
	metadataBytes, err := json.Marshal(metadata)
	if err != nil {
		return "", fmt.Errorf("failed to marshal metadata: %v", err)
	}

	if _, err := metadataFile.Write(metadataBytes); err != nil {
		return "", fmt.Errorf("failed to write metadata: %v", err)
	}

	return metadataFilePath, nil
}

// DecryptFile decrypts a file that was encrypted with EncryptFile
// Returns the path to the decrypted file
func DecryptFile(metadataFilePath string) (string, error) {
	// We don't need to create a user for decryption since we'll use the public key from metadata
	// for signature verification

	// Open the metadata file
	metadataFile, err := os.Open(metadataFilePath)
	if err != nil {
		return "", fmt.Errorf("failed to open metadata file: %v", err)
	}
	defer metadataFile.Close()

	// Read metadata
	metadataBytes, err := io.ReadAll(metadataFile)
	if err != nil {
		return "", fmt.Errorf("failed to read metadata: %v", err)
	}

	// Unmarshal metadata
	var metadata FileMetadata
	if err := json.Unmarshal(metadataBytes, &metadata); err != nil {
		return "", fmt.Errorf("failed to unmarshal metadata: %v", err)
	}

	// Create output file
	outDir := "out"
	decryptedFilePath := filepath.Join(outDir, "decrypted_"+metadata.OriginalName)
	decryptedFile, err := os.Create(decryptedFilePath)
	if err != nil {
		return "", fmt.Errorf("failed to create output file: %v", err)
	}
	defer decryptedFile.Close()

	// Deserialize the signer's public key from metadata
	signerKeyPair, err := crypto.DeserializeSignaturePublicKey(metadata.SignerPublicKey)
	if err != nil {
		return "", fmt.Errorf("failed to deserialize signer's public key: %v", err)
	}

	// Process all chunks in order
	for chunkIndex := uint32(0); chunkIndex < metadata.TotalChunks; chunkIndex++ {
		// Construct chunk file path
		chunkFilePath := filepath.Join(filepath.Dir(metadataFilePath),
			fmt.Sprintf("%s.chunk.%d", metadata.OriginalName, chunkIndex))

		// Open chunk file
		chunkFile, err := os.Open(chunkFilePath)
		if err != nil {
			return "", fmt.Errorf("failed to open chunk file %d: %v", chunkIndex, err)
		}

		// Read chunk file content
		chunkFileBytes, err := io.ReadAll(chunkFile)
		chunkFile.Close()
		if err != nil {
			return "", fmt.Errorf("failed to read chunk file %d: %v", chunkIndex, err)
		}

		// Unmarshal chunk
		var chunk FileChunk
		if err := json.Unmarshal(chunkFileBytes, &chunk); err != nil {
			return "", fmt.Errorf("failed to unmarshal chunk %d: %v", chunkIndex, err)
		}

		// Verify chunk index
		if chunk.Index != chunkIndex {
			return "", fmt.Errorf("chunk index mismatch: expected %d, got %d", chunkIndex, chunk.Index)
		}

		fmt.Printf("Read chunk %d from file %s\n", chunkIndex, chunkFilePath)

		// Create context info for this chunk using filename and chunk index
		contextInfo := fmt.Sprintf("file:%s:chunk:%d", metadata.OriginalName, chunkIndex)

		// Decrypt the chunk data using HKDF with key commitment verification
		decryptedData, err := crypto.DecryptAESGCMWithHKDF(chunk.Data, metadata.MasterKey, contextInfo, chunk.Commitment)
		if err != nil {
			return "", fmt.Errorf("failed to decrypt chunk %d: %v", chunkIndex, err)
		}

		// Verify the signature using the signer's public key
		valid, err := crypto.VerifySignature(signerKeyPair, decryptedData, chunk.Signature)
		if err != nil {
			return "", fmt.Errorf("signature verification error for chunk %d: %v", chunkIndex, err)
		}
		if !valid {
			return "", fmt.Errorf("invalid signature for chunk %d", chunkIndex)
		}

		// Write the decrypted data to the output file
		if _, err := decryptedFile.Write(decryptedData); err != nil {
			return "", fmt.Errorf("failed to write decrypted data: %v", err)
		}

		fmt.Printf("Processed chunk %d/%d\n", chunkIndex+1, metadata.TotalChunks)
	}

	return decryptedFilePath, nil
}
