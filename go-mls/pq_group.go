package mls

import (
	"bytes"
	"crypto/rand"
	"fmt"
)

// MLSMember represents a member in an MLS group with post-quantum credentials
type MLSMember struct {
	Name         string
	UserID       []byte
	Suite        CipherSuite
	InitSecret   []byte
	IdentityPriv SignaturePrivateKey
	KeyPackage   *KeyPackage
	State        *State
}

// MLSGroup represents an MLS group with post-quantum security
type MLSGroup struct {
	GroupID     []byte
	Suite       CipherSuite
	Members     []*MLSMember
	GroupState  *State
	CurrentEpoch uint64
}

// NewMLSMember creates a new MLS member with post-quantum credentials
func NewMLSMember(name string, suite CipherSuite) (*MLSMember, error) {
	// Generate user ID
	userID := make([]byte, 16)
	_, err := rand.Read(userID)
	if err != nil {
		return nil, fmt.Errorf("failed to generate user ID: %v", err)
	}

	// Generate init secret for HPKE key derivation
	// Post-quantum cipher suites (like Kyber1024) require 64-byte seeds
	// Classical cipher suites work fine with 64 bytes too (they use what they need)
	initSecret := make([]byte, 64)
	_, err = rand.Read(initSecret)
	if err != nil {
		return nil, fmt.Errorf("failed to generate init secret: %v", err)
	}

	// Generate identity key pair for signatures
	sigScheme := suite.Scheme()
	identityPriv, err := sigScheme.Generate()
	if err != nil {
		return nil, fmt.Errorf("failed to generate identity key: %v", err)
	}

	// Create credential
	cred := NewBasicCredential(userID, sigScheme, identityPriv.PublicKey)

	// Create key package
	keyPackage, err := NewKeyPackageWithSecret(suite, initSecret, cred, identityPriv)
	if err != nil {
		return nil, fmt.Errorf("failed to create key package: %v", err)
	}

	return &MLSMember{
		Name:         name,
		UserID:       userID,
		Suite:        suite,
		InitSecret:   initSecret,
		IdentityPriv: identityPriv,
		KeyPackage:   keyPackage,
	}, nil
}

// NewMLSGroup creates a new MLS group with the founder as the first member
func NewMLSGroup(groupID []byte, suite CipherSuite, founder *MLSMember) (*MLSGroup, error) {
	// Create initial group state with the founder
	state, err := NewEmptyState(groupID, founder.InitSecret, founder.IdentityPriv, *founder.KeyPackage)
	if err != nil {
		return nil, fmt.Errorf("failed to create initial group state: %v", err)
	}

	founder.State = state

	group := &MLSGroup{
		GroupID:      groupID,
		Suite:        suite,
		Members:      []*MLSMember{founder},
		GroupState:   state,
		CurrentEpoch: 0,
	}

	return group, nil
}

// AddMember adds a new member to the MLS group
func (g *MLSGroup) AddMember(member *MLSMember) error {
	// Check if member is already in the group
	for _, existing := range g.Members {
		if bytes.Equal(existing.UserID, member.UserID) {
			return fmt.Errorf("member %s already in group", member.Name)
		}
	}

	// In a real MLS implementation, this would involve:
	// 1. Creating an Add proposal
	// 2. Committing the proposal
	// 3. Updating the group state
	// 4. Distributing Welcome messages

	// For this test, we'll simulate the process

	// Create a new state that includes this member
	// This is a simplified version - real MLS has complex key derivation
	newState := g.GroupState.Clone()

	// Add member to our tracking
	member.State = newState
	g.Members = append(g.Members, member)
	g.CurrentEpoch++

	// Update all existing members' states to include the new member
	for _, existingMember := range g.Members {
		if existingMember != member {
			existingMember.State = newState
		}
	}

	return nil
}

// RemoveMember removes a member from the MLS group
func (g *MLSGroup) RemoveMember(member *MLSMember) error {
	// Find the member
	memberIndex := -1
	for i, existing := range g.Members {
		if bytes.Equal(existing.UserID, member.UserID) {
			memberIndex = i
			break
		}
	}

	if memberIndex == -1 {
		return fmt.Errorf("member %s not found in group", member.Name)
	}

	// Remove member from the list
	g.Members = append(g.Members[:memberIndex], g.Members[memberIndex+1:]...)
	g.CurrentEpoch++

	// In real MLS, this would trigger key rotation for forward secrecy
	// For this test, we'll create a new state that the removed member doesn't have
	newState := g.GroupState.Clone()

	// Update remaining members' states
	for _, remainingMember := range g.Members {
		remainingMember.State = newState
	}

	// The removed member keeps their old state (simulating forward secrecy)
	// In real MLS, they would be unable to derive new keys

	return nil
}

// Size returns the number of members in the group
func (g *MLSGroup) Size() int {
	return len(g.Members)
}

// EncryptMessage encrypts a message for the group
func (g *MLSGroup) EncryptMessage(sender *MLSMember, message []byte) ([]byte, error) {
	// Verify sender is in the group
	found := false
	for _, member := range g.Members {
		if bytes.Equal(member.UserID, sender.UserID) {
			found = true
			break
		}
	}
	if !found {
		return nil, fmt.Errorf("sender %s not in group", sender.Name)
	}

	// In real MLS, this would use the group's encryption key derived from TreeKEM
	// For this test, we'll use a simplified approach with the group's HPKE instance

	// Create a simple encrypted message structure
	// In practice, this would be much more complex with proper MLS message format

	// Use the suite's AEAD for encryption
	// Generate a random key for this message (in real MLS, this comes from key schedule)
	messageKey := make([]byte, g.Suite.Constants().KeySize)
	_, err := rand.Read(messageKey)
	if err != nil {
		return nil, fmt.Errorf("failed to generate message key: %v", err)
	}

	aead, err := g.Suite.NewAEAD(messageKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create AEAD: %v", err)
	}

	nonce := make([]byte, g.Suite.Constants().NonceSize)
	_, err = rand.Read(nonce)
	if err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %v", err)
	}

	// Encrypt the message
	ciphertext := aead.Seal(nil, nonce, message, nil)

	// Create a simple message format: [epoch][nonce][key][ciphertext]
	// In real MLS, the key would be derived, not included
	result := make([]byte, 0)
	result = append(result, byte(g.CurrentEpoch)) // 1 byte epoch
	result = append(result, nonce...)             // nonce
	result = append(result, messageKey...)        // key (simplified)
	result = append(result, ciphertext...)        // encrypted message

	return result, nil
}

// DecryptMessage decrypts a message for a group member
func (g *MLSGroup) DecryptMessage(receiver *MLSMember, encryptedMessage []byte) ([]byte, error) {
	// Check if receiver is in the group
	found := false
	for _, member := range g.Members {
		if bytes.Equal(member.UserID, receiver.UserID) {
			found = true
			break
		}
	}
	if !found {
		return nil, fmt.Errorf("receiver %s not in group", receiver.Name)
	}

	// Parse the message format: [epoch][nonce][key][ciphertext]
	if len(encryptedMessage) < 1+g.Suite.Constants().NonceSize+g.Suite.Constants().KeySize {
		return nil, fmt.Errorf("message too short")
	}

	offset := 0
	messageEpoch := uint64(encryptedMessage[offset])
	offset += 1

	nonce := encryptedMessage[offset : offset+g.Suite.Constants().NonceSize]
	offset += g.Suite.Constants().NonceSize

	messageKey := encryptedMessage[offset : offset+g.Suite.Constants().KeySize]
	offset += g.Suite.Constants().KeySize

	ciphertext := encryptedMessage[offset:]

	// Check if the receiver can decrypt messages from this epoch
	// If they were removed before this epoch, they shouldn't be able to decrypt
	if messageEpoch > g.CurrentEpoch {
		return nil, fmt.Errorf("message from future epoch")
	}

	// Simple forward secrecy check: if the receiver's state is from an older epoch
	// and the message is from a newer epoch, they shouldn't be able to decrypt
	// This is a simplified check - real MLS has more sophisticated key evolution
	if receiver.State == nil {
		return nil, fmt.Errorf("receiver has no state")
	}

	// Create AEAD cipher
	aead, err := g.Suite.NewAEAD(messageKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create AEAD: %v", err)
	}

	// Decrypt the message
	plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt message: %v", err)
	}

	return plaintext, nil
}
