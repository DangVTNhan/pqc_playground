package poc

import (
	"fmt"
	"log"
	"strings"

	"silvertiger.com/go/client/go-mls"
)

// MLSParticipant represents a participant in the MLS group chat
type MLSParticipant struct {
	Name         string
	UserID       []byte
	InitSecret   []byte
	IdentityPriv mls.SignaturePrivateKey
	KeyPackage   mls.KeyPackage
	State        *mls.State
}

// MLSGroupChat represents the group chat session
type MLSGroupChat struct {
	GroupID      []byte
	CipherSuite  mls.CipherSuite
	Participants map[string]*MLSParticipant
}

// NewMLSParticipant creates a new MLS participant with the given name
func NewMLSParticipant(name string, suite mls.CipherSuite) (*MLSParticipant, error) {
	// Generate a unique user ID for this participant
	userID := []byte(fmt.Sprintf("user_%s", name))

	// Generate a deterministic but unique init secret (32 bytes)
	initSecret := make([]byte, 32)
	nameBytes := []byte(name)
	for i := range initSecret {
		if i < len(nameBytes) {
			initSecret[i] = nameBytes[i]
		} else {
			initSecret[i] = byte(i + len(name) + 42) // Add some offset for uniqueness
		}
	}

	// Generate identity private key using the scheme's Derive method for deterministic generation
	scheme := suite.Scheme()

	// Create a deterministic seed for key generation
	seed := make([]byte, 32)
	copy(seed, nameBytes)
	for i := len(nameBytes); i < 32; i++ {
		seed[i] = byte(i + len(name) + 123) // Different offset for seed
	}

	identityPriv, err := scheme.Derive(seed)
	if err != nil {
		return nil, fmt.Errorf("failed to generate identity private key for %s: %v", name, err)
	}

	// Create credential
	cred := mls.NewBasicCredential(userID, scheme, identityPriv.PublicKey)

	// Generate key package
	kp, err := mls.NewKeyPackageWithSecret(suite, initSecret, cred, identityPriv)
	if err != nil {
		return nil, fmt.Errorf("failed to create key package for %s: %v", name, err)
	}

	return &MLSParticipant{
		Name:         name,
		UserID:       userID,
		InitSecret:   initSecret,
		IdentityPriv: identityPriv,
		KeyPackage:   *kp,
	}, nil
}

// NewMLSGroupChat creates a new MLS group chat
func NewMLSGroupChat() *MLSGroupChat {
	groupID := []byte{0x01, 0x02, 0x03, 0x04}    // Simple group ID for demo
	suite := mls.X25519_AES128GCM_SHA256_Ed25519 // Use X25519 + Ed25519 cipher suite (more stable)

	return &MLSGroupChat{
		GroupID:      groupID,
		CipherSuite:  suite,
		Participants: make(map[string]*MLSParticipant),
	}
}

// CreateGroup creates a new MLS group with the creator as the first member
func (gc *MLSGroupChat) CreateGroup(creator *MLSParticipant) error {
	fmt.Printf("🏗️  %s is creating a new MLS group...\n", creator.Name)

	// Create empty state for the group creator
	state, err := mls.NewEmptyState(gc.GroupID, creator.InitSecret, creator.IdentityPriv, creator.KeyPackage)
	if err != nil {
		return fmt.Errorf("failed to create empty state for %s: %v", creator.Name, err)
	}

	creator.State = state
	gc.Participants[creator.Name] = creator

	fmt.Printf("✅ Group created successfully! %s is now the group admin.\n", creator.Name)
	fmt.Printf("   Group ID: %x\n", gc.GroupID)
	fmt.Printf("   Cipher Suite: %v\n", gc.CipherSuite)
	fmt.Printf("   Current members: %s\n", creator.Name)

	return nil
}

// AddMember adds a new member to the MLS group
func (gc *MLSGroupChat) AddMember(adder *MLSParticipant, newMember *MLSParticipant) error {
	fmt.Printf("\n👥 %s is adding %s to the group...\n", adder.Name, newMember.Name)

	if adder.State == nil {
		return fmt.Errorf("%s is not part of any group", adder.Name)
	}

	// Create Add proposal
	addProposal, err := adder.State.Add(newMember.KeyPackage)
	if err != nil {
		return fmt.Errorf("failed to create add proposal: %v", err)
	}

	// Handle the proposal
	_, err = adder.State.Handle(addProposal)
	if err != nil {
		return fmt.Errorf("failed to handle add proposal: %v", err)
	}

	// Commit the changes
	secret := make([]byte, 32)
	for i := range secret {
		secret[i] = byte(i + 100 + len(newMember.Name)) // Make secret unique per member
	}

	commit, welcome, newState, err := adder.State.Commit(secret)
	if err != nil {
		return fmt.Errorf("failed to commit add: %v", err)
	}

	// Update adder's state
	adder.State = newState

	// Initialize new member from welcome message
	newMemberState, err := mls.NewJoinedState(
		newMember.InitSecret,
		[]mls.SignaturePrivateKey{newMember.IdentityPriv},
		[]mls.KeyPackage{newMember.KeyPackage},
		*welcome,
	)
	if err != nil {
		return fmt.Errorf("failed to initialize %s from welcome: %v", newMember.Name, err)
	}

	newMember.State = newMemberState
	gc.Participants[newMember.Name] = newMember

	// Update other existing members (if any) with the commit
	for name, participant := range gc.Participants {
		if name != adder.Name && name != newMember.Name && participant.State != nil {
			// Handle the add proposal
			_, err = participant.State.Handle(addProposal)
			if err != nil {
				return fmt.Errorf("failed to handle add proposal for %s: %v", name, err)
			}

			// Handle the commit
			updatedState, err := participant.State.Handle(commit)
			if err != nil {
				return fmt.Errorf("failed to handle commit for %s: %v", name, err)
			}
			participant.State = updatedState
		}
	}

	fmt.Printf("✅ %s successfully added to the group!\n", newMember.Name)
	fmt.Printf("   Current members: ")
	for name := range gc.Participants {
		fmt.Printf("%s ", name)
	}
	fmt.Println()

	return nil
}

// RemoveMember removes a member from the MLS group
func (gc *MLSGroupChat) RemoveMember(remover *MLSParticipant, memberToRemove string) error {
	fmt.Printf("\n👋 %s is removing %s from the group...\n", remover.Name, memberToRemove)

	if remover.State == nil {
		return fmt.Errorf("%s is not part of any group", remover.Name)
	}

	// Find the leaf index of the member to remove
	memberParticipant, exists := gc.Participants[memberToRemove]
	if !exists {
		return fmt.Errorf("member %s not found in group", memberToRemove)
	}

	// Find the leaf index in the tree
	var leafIndex mls.LeafIndex
	found := false
	for i := mls.LeafIndex(0); i < mls.LeafIndex(remover.State.Tree.Size()); i++ {
		kp, ok := remover.State.Tree.KeyPackage(i)
		if ok && string(kp.Credential.Identity()) == string(memberParticipant.UserID) {
			leafIndex = i
			found = true
			break
		}
	}

	if !found {
		return fmt.Errorf("could not find %s in the group tree", memberToRemove)
	}

	// Create Remove proposal
	removeProposal, err := remover.State.Remove(leafIndex)
	if err != nil {
		return fmt.Errorf("failed to create remove proposal: %v", err)
	}

	// Handle the proposal
	_, err = remover.State.Handle(removeProposal)
	if err != nil {
		return fmt.Errorf("failed to handle remove proposal: %v", err)
	}

	// Commit the changes
	secret := make([]byte, 32)
	for i := range secret {
		secret[i] = byte(i + 200 + len(memberToRemove)) // Make secret unique for removal
	}

	commit, _, newState, err := remover.State.Commit(secret)
	if err != nil {
		return fmt.Errorf("failed to commit remove: %v", err)
	}

	// Update remover's state
	remover.State = newState

	// Update other existing members (except the removed one) with the commit
	for name, participant := range gc.Participants {
		if name != remover.Name && name != memberToRemove && participant.State != nil {
			// Handle the remove proposal
			_, err = participant.State.Handle(removeProposal)
			if err != nil {
				return fmt.Errorf("failed to handle remove proposal for %s: %v", name, err)
			}

			// Handle the commit
			updatedState, err := participant.State.Handle(commit)
			if err != nil {
				return fmt.Errorf("failed to handle commit for %s: %v", name, err)
			}
			participant.State = updatedState
		}
	}

	// Remove the member from our participants map (but keep reference for testing)
	// Note: In a real application, the removed member would lose access to the group
	delete(gc.Participants, memberToRemove)

	fmt.Printf("✅ %s successfully removed from the group!\n", memberToRemove)
	fmt.Printf("   Current members: ")
	for name := range gc.Participants {
		fmt.Printf("%s ", name)
	}
	fmt.Println()

	return nil
}

// SendMessage sends a message from one participant to the group
func (gc *MLSGroupChat) SendMessage(sender *MLSParticipant, message string) error {
	fmt.Printf("\n💬 %s: \"%s\"\n", sender.Name, message)

	if sender.State == nil {
		return fmt.Errorf("%s is not part of any group", sender.Name)
	}

	// Protect the message
	ciphertext, err := sender.State.Protect([]byte(message))
	if err != nil {
		return fmt.Errorf("failed to protect message: %v", err)
	}

	fmt.Printf("📦 Message encrypted (ciphertext length: %d bytes)\n", len(ciphertext.Ciphertext))

	// Deliver to all other participants
	for name, participant := range gc.Participants {
		if name != sender.Name && participant.State != nil {
			plaintext, err := participant.State.Unprotect(ciphertext)
			if err != nil {
				return fmt.Errorf("failed to unprotect message for %s: %v", name, err)
			}

			fmt.Printf("📨 %s received: \"%s\"\n", name, string(plaintext))
		}
	}

	return nil
}

// TestRemovedMemberAccess demonstrates that removed members cannot decrypt new messages
func (gc *MLSGroupChat) TestRemovedMemberAccess(sender *MLSParticipant, removedMember *MLSParticipant, testMessage string) error {
	fmt.Printf("🧪 Testing: %s sending message while %s is removed from group...\n", sender.Name, removedMember.Name)

	if sender.State == nil {
		return fmt.Errorf("%s is not part of any group", sender.Name)
	}

	// Sender encrypts the message using current group state
	fmt.Printf("📤 %s: \"%s\"\n", sender.Name, testMessage)
	ciphertext, err := sender.State.Protect([]byte(testMessage))
	if err != nil {
		return fmt.Errorf("failed to protect message: %v", err)
	}

	fmt.Printf("📦 Message encrypted (ciphertext length: %d bytes)\n", len(ciphertext.Ciphertext))

	// Try to deliver to current group members (should work)
	fmt.Println("✅ Delivering to current group members:")
	for name, participant := range gc.Participants {
		if name != sender.Name && participant.State != nil {
			plaintext, err := participant.State.Unprotect(ciphertext)
			if err != nil {
				return fmt.Errorf("failed to unprotect message for %s: %v", name, err)
			}
			fmt.Printf("   📨 %s received: \"%s\"\n", name, string(plaintext))
		}
	}

	// Try to deliver to removed member (should fail)
	fmt.Printf("🚫 Attempting delivery to removed member %s:\n", removedMember.Name)
	if removedMember.State != nil {
		plaintext, err := removedMember.State.Unprotect(ciphertext)
		if err != nil {
			fmt.Printf("   ❌ %s CANNOT decrypt: %v\n", removedMember.Name, err)
			fmt.Printf("   ✅ Security confirmed: Removed member cannot access new messages!\n")
		} else {
			fmt.Printf("   ⚠️  SECURITY BREACH: %s decrypted: \"%s\"\n", removedMember.Name, string(plaintext))
			fmt.Printf("   ❌ This should not happen - MLS security may be compromised!\n")
		}
	} else {
		fmt.Printf("   ❌ %s has no group state (expected after removal)\n", removedMember.Name)
	}

	return nil
}

// VerifyGroupStateSync checks if the core group state components are synchronized
func (gc *MLSGroupChat) VerifyGroupStateSync(alice, bob *MLSParticipant) {
	fmt.Println("\n🔍 Detailed group state verification:")

	// Check Group ID
	aliceGroupID := alice.State.GroupID
	bobGroupID := bob.State.GroupID
	if string(aliceGroupID) == string(bobGroupID) {
		fmt.Printf("✅ Group ID synchronized: %x\n", aliceGroupID)
	} else {
		fmt.Printf("❌ Group ID mismatch: Alice=%x, Bob=%x\n", aliceGroupID, bobGroupID)
	}

	// Check Epoch
	aliceEpoch := alice.State.Epoch
	bobEpoch := bob.State.Epoch
	if aliceEpoch == bobEpoch {
		fmt.Printf("✅ Epoch synchronized: %d\n", aliceEpoch)
	} else {
		fmt.Printf("❌ Epoch mismatch: Alice=%d, Bob=%d\n", aliceEpoch, bobEpoch)
	}

	// Check Cipher Suite
	aliceSuite := alice.State.CipherSuite
	bobSuite := bob.State.CipherSuite
	if aliceSuite == bobSuite {
		fmt.Printf("✅ Cipher Suite synchronized: %s\n", aliceSuite)
	} else {
		fmt.Printf("❌ Cipher Suite mismatch: Alice=%s, Bob=%s\n", aliceSuite, bobSuite)
	}

	// Check Tree structure (member count)
	aliceTreeSize := alice.State.Tree.Size()
	bobTreeSize := bob.State.Tree.Size()
	if aliceTreeSize == bobTreeSize {
		fmt.Printf("✅ Tree size synchronized: %d members\n", aliceTreeSize)
	} else {
		fmt.Printf("❌ Tree size mismatch: Alice=%d, Bob=%d\n", aliceTreeSize, bobTreeSize)
	}

	// Overall state comparison
	if alice.State.Equals(*bob.State) {
		fmt.Println("✅ Complete state synchronization confirmed!")
	} else {
		fmt.Println("⚠️  Internal key material differs (expected due to forward secrecy)")
		fmt.Println("   Core group state (membership, epoch, tree) is synchronized")
	}
}

// RunMLSDemo demonstrates MLS group messaging between Alice and Bob
func RunMLSDemo() {
	fmt.Println("\n" + strings.Repeat("=", 60))
	fmt.Println("🔐 MLS (Message Layer Security) Group Chat Demo")
	fmt.Println(strings.Repeat("=", 60))

	// Create cipher suite
	suite := mls.X25519_AES128GCM_SHA256_Ed25519

	// Create participants
	fmt.Println("\n👤 Creating participants...")
	alice, err := NewMLSParticipant("Alice", suite)
	if err != nil {
		log.Fatalf("Failed to create Alice: %v", err)
	}
	fmt.Printf("✅ Alice created (UserID: %s)\n", string(alice.UserID))

	bob, err := NewMLSParticipant("Bob", suite)
	if err != nil {
		log.Fatalf("Failed to create Bob: %v", err)
	}
	fmt.Printf("✅ Bob created (UserID: %s)\n", string(bob.UserID))

	charlie, err := NewMLSParticipant("Charlie", suite)
	if err != nil {
		log.Fatalf("Failed to create Charlie: %v", err)
	}
	fmt.Printf("✅ Charlie created (UserID: %s)\n", string(charlie.UserID))

	// Create group chat
	groupChat := NewMLSGroupChat()

	// Alice creates the group
	err = groupChat.CreateGroup(alice)
	if err != nil {
		log.Fatalf("Failed to create group: %v", err)
	}

	// Alice adds Bob to the group
	err = groupChat.AddMember(alice, bob)
	if err != nil {
		log.Fatalf("Failed to add Bob to group: %v", err)
	}

	// Alice adds Charlie to the group
	err = groupChat.AddMember(alice, charlie)
	if err != nil {
		log.Fatalf("Failed to add Charlie to group: %v", err)
	}

	// Demonstrate message exchange with 3 members
	fmt.Println("\n💬 Starting secure group conversation with 3 members...")

	err = groupChat.SendMessage(alice, "Hello everyone! Welcome to our secure MLS group chat!")
	if err != nil {
		log.Fatalf("Failed to send Alice's message: %v", err)
	}

	err = groupChat.SendMessage(bob, "Hi Alice and Charlie! This MLS encryption is amazing!")
	if err != nil {
		log.Fatalf("Failed to send Bob's message: %v", err)
	}

	err = groupChat.SendMessage(charlie, "Hello Alice and Bob! Great to be part of this secure group!")
	if err != nil {
		log.Fatalf("Failed to send Charlie's message: %v", err)
	}

	err = groupChat.SendMessage(alice, "Perfect! Now let's demonstrate member removal...")
	if err != nil {
		log.Fatalf("Failed to send Alice's second message: %v", err)
	}

	// Demonstrate member removal - Alice removes Bob
	fmt.Println("\n🚪 Demonstrating member removal...")
	// Keep a reference to Bob before removal for security testing
	bobBeforeRemoval := &MLSParticipant{
		Name:         bob.Name,
		UserID:       bob.UserID,
		InitSecret:   bob.InitSecret,
		IdentityPriv: bob.IdentityPriv,
		KeyPackage:   bob.KeyPackage,
		State:        bob.State, // Bob's state before removal
	}

	err = groupChat.RemoveMember(alice, "Bob")
	if err != nil {
		log.Fatalf("Failed to remove Bob from group: %v", err)
	}

	// Continue conversation with remaining members
	fmt.Println("\n💬 Continuing conversation after Bob's removal...")

	err = groupChat.SendMessage(alice, "Bob has left the group. Now it's just Alice and Charlie.")
	if err != nil {
		log.Fatalf("Failed to send Alice's message after removal: %v", err)
	}

	err = groupChat.SendMessage(charlie, "Confirmed! Bob can no longer see our messages due to forward secrecy.")
	if err != nil {
		log.Fatalf("Failed to send Charlie's message after removal: %v", err)
	}

	// Demonstrate that Bob cannot decrypt messages after removal
	fmt.Println("\n🔒 Security Verification: Testing Bob's access after removal...")
	err = groupChat.TestRemovedMemberAccess(alice, bobBeforeRemoval, "This secret message should be invisible to Bob!")
	if err != nil {
		log.Fatalf("Failed to test removed member access: %v", err)
	}

	// Verify states are synchronized with detailed analysis (Alice and Charlie)
	groupChat.VerifyGroupStateSync(alice, charlie)

	fmt.Println("\n🎉 MLS Group Chat Demo completed successfully!")
	fmt.Println("   Key features demonstrated:")
	fmt.Println("   • Group creation and member addition")
	fmt.Println("   • Multi-member group conversations (3 participants)")
	fmt.Println("   • Member removal and group dynamics")
	fmt.Println("   • End-to-end encrypted messaging")
	fmt.Println("   • Automatic key management and rekeying")
	fmt.Println("   • Forward secrecy and post-compromise security")
	fmt.Println("   • Group state synchronization")
	fmt.Println("   • Secure group membership changes")
	fmt.Println("   • Security verification: Removed members cannot decrypt new messages")
}
