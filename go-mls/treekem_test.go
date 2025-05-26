package mls

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"testing"
)

// TestTreeKEMPostQuantum tests TreeKEM operations with the post-quantum cipher suite
func TestTreeKEMPostQuantum(t *testing.T) {
	fmt.Println("\n=== TreeKEM Post-Quantum Test ===")

	suite := KYBER1024_AES256GCM_SHA512_DILITHIUM3

	// Test basic TreeKEM public key creation
	pub := NewTreeKEMPublicKey(suite)
	if pub.Suite != suite {
		t.Fatalf("Expected suite %v, got %v", suite, pub.Suite)
	}

	// Create test credentials and key packages
	members := make([]KeyPackage, 3)
	sigKeys := make([]SignaturePrivateKey, 3)
	memberNames := []string{"Alice", "Bob", "Charlie"}

	for i := 0; i < 3; i++ {
		// Generate signature key pair
		sigScheme := suite.Scheme()
		sigKey, err := sigScheme.Generate()
		if err != nil {
			t.Fatalf("Failed to generate signature key for %s: %v", memberNames[i], err)
		}
		sigKeys[i] = sigKey

		// Generate HPKE key pair
		hpkeInstance := suite.Hpke()
		hpkeKey, err := hpkeInstance.Generate()
		if err != nil {
			t.Fatalf("Failed to generate HPKE key for %s: %v", memberNames[i], err)
		}

		// Create credential
		cred := NewBasicCredential([]byte(memberNames[i]), suite.Scheme(), sigKey.PublicKey)

		// Create key package
		keyPkg, err := NewKeyPackageWithInitKey(suite, hpkeKey.PublicKey, cred, sigKey)
		if err != nil {
			t.Fatalf("Failed to create key package for %s: %v", memberNames[i], err)
		}

		members[i] = *keyPkg
		fmt.Printf("✓ Created key package for %s\n", memberNames[i])
	}

	// Add members to the tree
	indices := make([]LeafIndex, 3)
	for i, member := range members {
		index := pub.AddLeaf(member)
		indices[i] = index
		fmt.Printf("✓ Added %s at leaf index %d\n", memberNames[i], index)
	}

	if pub.Size() != 3 {
		t.Fatalf("Expected tree size 3, got %d", pub.Size())
	}

	fmt.Printf("✓ TreeKEM public key created with %d members\n", pub.Size())
}

// TestTreeKEMEncapDecap tests the Encap/Decap operations with post-quantum crypto
func TestTreeKEMEncapDecap(t *testing.T) {
	fmt.Println("\n=== TreeKEM Encap/Decap Test ===")

	suite := KYBER1024_AES256GCM_SHA512_DILITHIUM3
	pub := NewTreeKEMPublicKey(suite)

	// Create two members
	memberNames := []string{"Alice", "Bob"}
	members := make([]KeyPackage, 2)
	sigKeys := make([]SignaturePrivateKey, 2)

	for i := 0; i < 2; i++ {
		// Generate keys and create key package
		sigScheme := suite.Scheme()
		sigKey, err := sigScheme.Generate()
		if err != nil {
			t.Fatalf("Failed to generate signature key: %v", err)
		}
		sigKeys[i] = sigKey

		hpkeInstance := suite.Hpke()
		hpkeKey, err := hpkeInstance.Generate()
		if err != nil {
			t.Fatalf("Failed to generate HPKE key: %v", err)
		}

		cred := NewBasicCredential([]byte(memberNames[i]), suite.Scheme(), sigKey.PublicKey)
		keyPkg, err := NewKeyPackageWithInitKey(suite, hpkeKey.PublicKey, cred, sigKey)
		if err != nil {
			t.Fatalf("Failed to create key package: %v", err)
		}

		members[i] = *keyPkg
		pub.AddLeaf(*keyPkg)
	}

	// Test Encap operation (Alice updates her key)
	aliceIndex := LeafIndex(0)
	bobIndex := LeafIndex(1)
	context := []byte("test-context")

	// Generate separate leaf secrets for Alice and Bob
	aliceLeafSecret := make([]byte, suite.Constants().SecretSize)
	_, err := rand.Read(aliceLeafSecret)
	if err != nil {
		t.Fatalf("Failed to generate Alice's leaf secret: %v", err)
	}

	bobLeafSecret := make([]byte, suite.Constants().SecretSize)
	_, err = rand.Read(bobLeafSecret)
	if err != nil {
		t.Fatalf("Failed to generate Bob's leaf secret: %v", err)
	}

	// Create TreeKEM private keys for both members
	alicePriv := NewTreeKEMPrivateKey(suite, pub.Size(), aliceIndex, aliceLeafSecret)
	bobPriv := NewTreeKEMPrivateKey(suite, pub.Size(), bobIndex, bobLeafSecret)

	// Update the public tree with the derived public keys
	aliceNodePriv, err := alicePriv.privateKey(toNodeIndex(aliceIndex))
	if err != nil {
		t.Fatalf("Failed to get Alice's node private key: %v", err)
	}
	bobNodePriv, err := bobPriv.privateKey(toNodeIndex(bobIndex))
	if err != nil {
		t.Fatalf("Failed to get Bob's node private key: %v", err)
	}

	// Update Alice's key package with the derived public key
	members[0].InitKey = aliceNodePriv.PublicKey
	err = members[0].Sign(sigKeys[0])
	if err != nil {
		t.Fatalf("Failed to re-sign Alice's key package: %v", err)
	}
	pub.UpdateLeaf(aliceIndex, members[0])

	// Update Bob's key package with the derived public key
	members[1].InitKey = bobNodePriv.PublicKey
	err = members[1].Sign(sigKeys[1])
	if err != nil {
		t.Fatalf("Failed to re-sign Bob's key package: %v", err)
	}
	pub.UpdateLeaf(bobIndex, members[1])

	fmt.Println("Testing Encap operation...")
	// Generate a new leaf secret for Alice's update
	newAliceLeafSecret := make([]byte, suite.Constants().SecretSize)
	_, err = rand.Read(newAliceLeafSecret)
	if err != nil {
		t.Fatalf("Failed to generate new Alice leaf secret: %v", err)
	}

	priv, path, err := pub.Encap(aliceIndex, context, newAliceLeafSecret, sigKeys[0], nil)
	if err != nil {
		t.Fatalf("Encap failed: %v", err)
	}

	if priv == nil || path == nil {
		t.Fatal("Encap returned nil private key or path")
	}

	fmt.Printf("✓ Encap successful - generated %d path steps\n", len(path.Steps))

	// Test Decap operation (Bob processes Alice's update)
	fmt.Println("Testing Decap operation...")
	err = bobPriv.Decap(aliceIndex, *pub, context, *path)
	if err != nil {
		t.Fatalf("Decap failed: %v", err)
	}

	fmt.Println("✓ Decap successful")

	// Verify consistency between Alice and Bob's private keys
	if !priv.Consistent(*bobPriv) {
		t.Fatal("Private keys are not consistent after Encap/Decap")
	}

	fmt.Println("✓ Private keys are consistent")
}

// TestTreeKEMSimpleDebug tests a very simple TreeKEM scenario for debugging
func TestTreeKEMSimpleDebug(t *testing.T) {
	fmt.Println("\n=== TreeKEM Simple Debug Test ===")

	suite := KYBER1024_AES256GCM_SHA512_DILITHIUM3
	pub := NewTreeKEMPublicKey(suite)

	// Create just Alice
	sigScheme := suite.Scheme()
	aliceSignKey, err := sigScheme.Generate()
	if err != nil {
		t.Fatalf("Failed to generate Alice's signature key: %v", err)
	}

	hpkeInstance := suite.Hpke()
	aliceHPKEKey, err := hpkeInstance.Generate()
	if err != nil {
		t.Fatalf("Failed to generate Alice's HPKE key: %v", err)
	}

	aliceCred := NewBasicCredential([]byte("Alice"), suite.Scheme(), aliceSignKey.PublicKey)
	aliceKeyPkg, err := NewKeyPackageWithInitKey(suite, aliceHPKEKey.PublicKey, aliceCred, aliceSignKey)
	if err != nil {
		t.Fatalf("Failed to create Alice's key package: %v", err)
	}

	aliceIndex := pub.AddLeaf(*aliceKeyPkg)
	fmt.Printf("✓ Added Alice at index %d\n", aliceIndex)

	// Create Bob
	bobSignKey, err := sigScheme.Generate()
	if err != nil {
		t.Fatalf("Failed to generate Bob's signature key: %v", err)
	}

	bobHPKEKey, err := hpkeInstance.Generate()
	if err != nil {
		t.Fatalf("Failed to generate Bob's HPKE key: %v", err)
	}

	bobCred := NewBasicCredential([]byte("Bob"), suite.Scheme(), bobSignKey.PublicKey)
	bobKeyPkg, err := NewKeyPackageWithInitKey(suite, bobHPKEKey.PublicKey, bobCred, bobSignKey)
	if err != nil {
		t.Fatalf("Failed to create Bob's key package: %v", err)
	}

	bobIndex := pub.AddLeaf(*bobKeyPkg)
	fmt.Printf("✓ Added Bob at index %d\n", bobIndex)

	// For TreeKEM to work, each member needs a private key that corresponds to their public key in the tree
	// The TreeKEM private key should be initialized with a leaf secret that derives to the same public key

	// Generate a leaf secret that will derive to Bob's HPKE key
	// We need to use the same seed that was used to generate Bob's HPKE key
	// Since we can't extract the seed, we'll create a new TreeKEM setup where both members
	// start with the same initial state

	// Generate leaf secrets for both Alice and Bob
	aliceLeafSecret := make([]byte, suite.Constants().SecretSize)
	_, err = rand.Read(aliceLeafSecret)
	if err != nil {
		t.Fatalf("Failed to generate Alice's leaf secret: %v", err)
	}

	bobLeafSecret := make([]byte, suite.Constants().SecretSize)
	_, err = rand.Read(bobLeafSecret)
	if err != nil {
		t.Fatalf("Failed to generate Bob's leaf secret: %v", err)
	}

	// Create TreeKEM private keys for both members
	// In a real scenario, these would be derived from the same initial group state
	alicePriv := NewTreeKEMPrivateKey(suite, pub.Size(), aliceIndex, aliceLeafSecret)
	bobPriv := NewTreeKEMPrivateKey(suite, pub.Size(), bobIndex, bobLeafSecret)

	// Update the public tree with the derived public keys
	aliceNodePriv, err := alicePriv.privateKey(toNodeIndex(aliceIndex))
	if err != nil {
		t.Fatalf("Failed to get Alice's node private key: %v", err)
	}
	bobNodePriv, err := bobPriv.privateKey(toNodeIndex(bobIndex))
	if err != nil {
		t.Fatalf("Failed to get Bob's node private key: %v", err)
	}

	// Update Alice's key package with the derived public key
	aliceKeyPkg.InitKey = aliceNodePriv.PublicKey
	err = aliceKeyPkg.Sign(aliceSignKey)
	if err != nil {
		t.Fatalf("Failed to re-sign Alice's key package: %v", err)
	}
	pub.UpdateLeaf(aliceIndex, *aliceKeyPkg)

	// Update Bob's key package with the derived public key
	bobKeyPkg.InitKey = bobNodePriv.PublicKey
	err = bobKeyPkg.Sign(bobSignKey)
	if err != nil {
		t.Fatalf("Failed to re-sign Bob's key package: %v", err)
	}
	pub.UpdateLeaf(bobIndex, *bobKeyPkg)

	fmt.Println("✓ Updated public tree with derived keys")

	context := []byte("debug-test")

	// Now Alice performs an update with a new leaf secret
	newAliceLeafSecret := make([]byte, suite.Constants().SecretSize)
	_, err = rand.Read(newAliceLeafSecret)
	if err != nil {
		t.Fatalf("Failed to generate new Alice leaf secret: %v", err)
	}

	fmt.Println("Testing Alice's update...")
	aliceNewPriv, path, err := pub.Encap(aliceIndex, context, newAliceLeafSecret, aliceSignKey, nil)
	if err != nil {
		t.Fatalf("Alice's Encap failed: %v", err)
	}

	fmt.Printf("✓ Alice's Encap successful with %d path steps\n", len(path.Steps))

	// Bob should be able to decrypt Alice's update using his existing private key
	err = bobPriv.Decap(aliceIndex, *pub, context, *path)
	if err != nil {
		t.Fatalf("Bob failed to decrypt Alice's update: %v", err)
	}

	fmt.Println("✓ Bob successfully decrypted Alice's update")

	// Check consistency between Alice's new private key and Bob's updated private key
	if !aliceNewPriv.Consistent(*bobPriv) {
		t.Fatal("Alice and Bob's private keys are not consistent after update")
	}

	fmt.Println("✓ Alice and Bob's private keys are consistent after update")
}

// TestTreeKEMKeyRotation tests key rotation functionality
func TestTreeKEMKeyRotation(t *testing.T) {
	fmt.Println("\n=== TreeKEM Key Rotation Test ===")

	suite := KYBER1024_AES256GCM_SHA512_DILITHIUM3
	pub := NewTreeKEMPublicKey(suite)

	// Create a member
	sigScheme := suite.Scheme()
	sigKey, err := sigScheme.Generate()
	if err != nil {
		t.Fatalf("Failed to generate signature key: %v", err)
	}

	hpkeInstance := suite.Hpke()
	hpkeKey, err := hpkeInstance.Generate()
	if err != nil {
		t.Fatalf("Failed to generate HPKE key: %v", err)
	}

	cred := NewBasicCredential([]byte("Alice"), suite.Scheme(), sigKey.PublicKey)
	keyPkg, err := NewKeyPackageWithInitKey(suite, hpkeKey.PublicKey, cred, sigKey)
	if err != nil {
		t.Fatalf("Failed to create key package: %v", err)
	}

	// Add to tree
	index := pub.AddLeaf(*keyPkg)
	fmt.Printf("✓ Added Alice at index %d\n", index)

	// Store original public key
	originalPubKey := keyPkg.InitKey

	// Test leaf key rotation
	fmt.Println("Testing leaf key rotation...")
	newKeyPkg, err := pub.RotateLeafKey(index, suite, sigKey)
	if err != nil {
		t.Fatalf("Failed to rotate leaf key: %v", err)
	}

	// Verify the key was actually rotated
	if newKeyPkg.InitKey.Equals(originalPubKey) {
		t.Fatal("Key rotation did not change the public key")
	}

	fmt.Println("✓ Leaf key rotated successfully")

	// Test private key rotation
	leafSecret := make([]byte, suite.Constants().SecretSize)
	_, err = rand.Read(leafSecret)
	if err != nil {
		t.Fatalf("Failed to generate leaf secret: %v", err)
	}

	priv := NewTreeKEMPrivateKey(suite, pub.Size(), index, leafSecret)
	originalUpdateSecret := make([]byte, len(priv.UpdateSecret))
	copy(originalUpdateSecret, priv.UpdateSecret)

	fmt.Println("Testing private key rotation...")
	err = priv.RotateKeys(pub.Size())
	if err != nil {
		t.Fatalf("Failed to rotate private keys: %v", err)
	}

	// Verify the update secret changed
	if bytes.Equal(originalUpdateSecret, priv.UpdateSecret) {
		t.Fatal("Private key rotation did not change the update secret")
	}

	fmt.Println("✓ Private key rotated successfully")
}

// TestTreeKEMMultiMember tests TreeKEM with multiple members and operations
func TestTreeKEMMultiMember(t *testing.T) {
	fmt.Println("\n=== TreeKEM Multi-Member Test ===")

	suite := KYBER1024_AES256GCM_SHA512_DILITHIUM3
	pub := NewTreeKEMPublicKey(suite)

	numMembers := 5
	memberNames := []string{"Alice", "Bob", "Charlie", "Diana", "Eve"}
	members := make([]KeyPackage, numMembers)
	sigKeys := make([]SignaturePrivateKey, numMembers)
	indices := make([]LeafIndex, numMembers)

	// Create and add all members
	fmt.Printf("Creating %d members...\n", numMembers)
	for i := 0; i < numMembers; i++ {
		// Generate keys
		sigScheme := suite.Scheme()
		sigKey, err := sigScheme.Generate()
		if err != nil {
			t.Fatalf("Failed to generate signature key for %s: %v", memberNames[i], err)
		}
		sigKeys[i] = sigKey

		hpkeInstance := suite.Hpke()
		hpkeKey, err := hpkeInstance.Generate()
		if err != nil {
			t.Fatalf("Failed to generate HPKE key for %s: %v", memberNames[i], err)
		}

		// Create key package
		cred := NewBasicCredential([]byte(memberNames[i]), suite.Scheme(), sigKey.PublicKey)
		keyPkg, err := NewKeyPackageWithInitKey(suite, hpkeKey.PublicKey, cred, sigKey)
		if err != nil {
			t.Fatalf("Failed to create key package for %s: %v", memberNames[i], err)
		}

		members[i] = *keyPkg
		indices[i] = pub.AddLeaf(*keyPkg)
		fmt.Printf("✓ Added %s at index %d\n", memberNames[i], indices[i])
	}

	if pub.Size() != LeafCount(numMembers) {
		t.Fatalf("Expected tree size %d, got %d", numMembers, pub.Size())
	}

	// Test member lookup
	fmt.Println("Testing member lookup...")
	for i, member := range members {
		foundIndex, found := pub.Find(member)
		if !found {
			t.Fatalf("Could not find member %s in tree", memberNames[i])
		}
		if foundIndex != indices[i] {
			t.Fatalf("Found member %s at wrong index: expected %d, got %d",
				memberNames[i], indices[i], foundIndex)
		}
	}
	fmt.Println("✓ All members found correctly")

	// Test key package retrieval
	fmt.Println("Testing key package retrieval...")
	for i, expectedIndex := range indices {
		keyPkg, found := pub.KeyPackage(expectedIndex)
		if !found {
			t.Fatalf("Could not retrieve key package for index %d", expectedIndex)
		}
		if !keyPkg.Equals(members[i]) {
			t.Fatalf("Retrieved key package does not match for %s", memberNames[i])
		}
	}
	fmt.Println("✓ All key packages retrieved correctly")

	// Test tree operations with multiple members
	fmt.Println("Testing Encap/Decap with multiple members...")

	// Alice (index 0) performs an update
	aliceIndex := indices[0]
	context := []byte("multi-member-test")

	// Generate separate leaf secrets for each member
	leafSecrets := make([][]byte, numMembers)
	memberPrivKeys := make([]*TreeKEMPrivateKey, numMembers)

	for i := 0; i < numMembers; i++ {
		leafSecrets[i] = make([]byte, suite.Constants().SecretSize)
		_, err := rand.Read(leafSecrets[i])
		if err != nil {
			t.Fatalf("Failed to generate leaf secret for %s: %v", memberNames[i], err)
		}
		memberPrivKeys[i] = NewTreeKEMPrivateKey(suite, pub.Size(), indices[i], leafSecrets[i])
	}

	// Update the public tree with the derived public keys
	for i := 0; i < numMembers; i++ {
		nodePriv, err := memberPrivKeys[i].privateKey(toNodeIndex(indices[i]))
		if err != nil {
			t.Fatalf("Failed to get node private key for %s: %v", memberNames[i], err)
		}

		// Update the key package with the derived public key
		members[i].InitKey = nodePriv.PublicKey
		err = members[i].Sign(sigKeys[i])
		if err != nil {
			t.Fatalf("Failed to re-sign key package for %s: %v", memberNames[i], err)
		}
		pub.UpdateLeaf(indices[i], members[i])
	}

	// Perform Encap with a new leaf secret for Alice's update
	newAliceLeafSecret := make([]byte, suite.Constants().SecretSize)
	_, err := rand.Read(newAliceLeafSecret)
	if err != nil {
		t.Fatalf("Failed to generate new Alice leaf secret: %v", err)
	}

	alicePriv, path, err := pub.Encap(aliceIndex, context, newAliceLeafSecret, sigKeys[0], nil)
	if err != nil {
		t.Fatalf("Alice's Encap failed: %v", err)
	}

	fmt.Printf("✓ Alice performed Encap with %d path steps\n", len(path.Steps))

	// All other members should be able to Decap
	for i := 1; i < numMembers; i++ {
		err = memberPrivKeys[i].Decap(aliceIndex, *pub, context, *path)
		if err != nil {
			t.Fatalf("%s's Decap failed: %v", memberNames[i], err)
		}

		// Verify consistency
		if !alicePriv.Consistent(*memberPrivKeys[i]) {
			t.Fatalf("%s's private key is not consistent with Alice's", memberNames[i])
		}

		fmt.Printf("✓ %s successfully processed Alice's update\n", memberNames[i])
	}

	fmt.Printf("✓ Multi-member TreeKEM operations completed successfully\n")
}

// TestTreeKEMWithKeyRotationScenario tests a realistic scenario with key rotation
func TestTreeKEMWithKeyRotationScenario(t *testing.T) {
	fmt.Println("\n=== TreeKEM Key Rotation Scenario Test ===")

	suite := KYBER1024_AES256GCM_SHA512_DILITHIUM3
	pub := NewTreeKEMPublicKey(suite)

	// Create 3 members
	numMembers := 3
	memberNames := []string{"Alice", "Bob", "Charlie"}
	members := make([]KeyPackage, numMembers)
	sigKeys := make([]SignaturePrivateKey, numMembers)
	indices := make([]LeafIndex, numMembers)
	privKeys := make([]*TreeKEMPrivateKey, numMembers)

	// Setup members
	fmt.Printf("Setting up %d members...\n", numMembers)
	for i := 0; i < numMembers; i++ {
		// Generate keys
		sigScheme := suite.Scheme()
		sigKey, err := sigScheme.Generate()
		if err != nil {
			t.Fatalf("Failed to generate signature key for %s: %v", memberNames[i], err)
		}
		sigKeys[i] = sigKey

		hpkeInstance := suite.Hpke()
		hpkeKey, err := hpkeInstance.Generate()
		if err != nil {
			t.Fatalf("Failed to generate HPKE key for %s: %v", memberNames[i], err)
		}

		// Create key package
		cred := NewBasicCredential([]byte(memberNames[i]), suite.Scheme(), sigKey.PublicKey)
		keyPkg, err := NewKeyPackageWithInitKey(suite, hpkeKey.PublicKey, cred, sigKey)
		if err != nil {
			t.Fatalf("Failed to create key package for %s: %v", memberNames[i], err)
		}

		members[i] = *keyPkg
		indices[i] = pub.AddLeaf(*keyPkg)
		fmt.Printf("✓ Added %s at index %d\n", memberNames[i], indices[i])
	}

	// Initialize private keys for all members
	leafSecrets := make([][]byte, numMembers)
	for i := 0; i < numMembers; i++ {
		leafSecrets[i] = make([]byte, suite.Constants().SecretSize)
		_, err := rand.Read(leafSecrets[i])
		if err != nil {
			t.Fatalf("Failed to generate leaf secret for %s: %v", memberNames[i], err)
		}
		privKeys[i] = NewTreeKEMPrivateKey(suite, pub.Size(), indices[i], leafSecrets[i])
	}

	// Update the public tree with the derived public keys
	for i := 0; i < numMembers; i++ {
		nodePriv, err := privKeys[i].privateKey(toNodeIndex(indices[i]))
		if err != nil {
			t.Fatalf("Failed to get node private key for %s: %v", memberNames[i], err)
		}

		// Update the key package with the derived public key
		members[i].InitKey = nodePriv.PublicKey
		err = members[i].Sign(sigKeys[i])
		if err != nil {
			t.Fatalf("Failed to re-sign key package for %s: %v", memberNames[i], err)
		}
		pub.UpdateLeaf(indices[i], members[i])
	}

	// Scenario 1: Alice rotates her key
	fmt.Println("\n--- Scenario 1: Alice rotates her key ---")
	aliceIndex := indices[0]

	// Rotate Alice's leaf key in the public tree
	_, err := pub.RotateLeafKey(aliceIndex, suite, sigKeys[0])
	if err != nil {
		t.Fatalf("Failed to rotate Alice's leaf key: %v", err)
	}
	fmt.Println("✓ Alice's leaf key rotated in public tree")

	// Alice performs Encap with new key material
	context := []byte("key-rotation-scenario")
	newAliceLeafSecret := make([]byte, suite.Constants().SecretSize)
	_, err = rand.Read(newAliceLeafSecret)
	if err != nil {
		t.Fatalf("Failed to generate new leaf secret: %v", err)
	}

	aliceNewPriv, path, err := pub.Encap(aliceIndex, context, newAliceLeafSecret, sigKeys[0], nil)
	if err != nil {
		t.Fatalf("Alice's Encap after key rotation failed: %v", err)
	}
	fmt.Printf("✓ Alice performed Encap with rotated key (%d path steps)\n", len(path.Steps))

	// Bob and Charlie process Alice's update
	for i := 1; i < numMembers; i++ {
		err = privKeys[i].Decap(aliceIndex, *pub, context, *path)
		if err != nil {
			t.Fatalf("%s failed to process Alice's rotated key update: %v", memberNames[i], err)
		}

		// Verify consistency
		if !aliceNewPriv.Consistent(*privKeys[i]) {
			t.Fatalf("%s's key is not consistent with Alice's after rotation", memberNames[i])
		}

		fmt.Printf("✓ %s processed Alice's key rotation successfully\n", memberNames[i])
	}

	// Update Alice's private key reference
	privKeys[0] = aliceNewPriv

	// Scenario 2: Multiple key rotations
	fmt.Println("\n--- Scenario 2: Bob rotates his key ---")
	bobIndex := indices[1]

	// Bob rotates his private key material
	err = privKeys[1].RotateKeys(pub.Size())
	if err != nil {
		t.Fatalf("Failed to rotate Bob's private key: %v", err)
	}
	fmt.Println("✓ Bob's private key material rotated")

	// Bob performs Encap with a new leaf secret
	newBobLeafSecret := make([]byte, suite.Constants().SecretSize)
	_, err = rand.Read(newBobLeafSecret)
	if err != nil {
		t.Fatalf("Failed to generate new Bob leaf secret: %v", err)
	}

	bobNewPriv, bobPath, err := pub.Encap(bobIndex, context, newBobLeafSecret, sigKeys[1], nil)
	if err != nil {
		t.Fatalf("Bob's Encap after key rotation failed: %v", err)
	}
	fmt.Printf("✓ Bob performed Encap with rotated key (%d path steps)\n", len(bobPath.Steps))

	// Alice and Charlie process Bob's update
	for i := 0; i < numMembers; i++ {
		if i == 1 { // Skip Bob himself
			continue
		}

		err = privKeys[i].Decap(bobIndex, *pub, context, *bobPath)
		if err != nil {
			t.Fatalf("%s failed to process Bob's rotated key update: %v", memberNames[i], err)
		}

		// Verify consistency
		if !bobNewPriv.Consistent(*privKeys[i]) {
			t.Fatalf("%s's key is not consistent with Bob's after rotation", memberNames[i])
		}

		fmt.Printf("✓ %s processed Bob's key rotation successfully\n", memberNames[i])
	}

	// Update Bob's private key reference
	privKeys[1] = bobNewPriv

	// Final verification: All members should have consistent keys
	fmt.Println("\n--- Final Verification ---")
	for i := 0; i < numMembers-1; i++ {
		for j := i + 1; j < numMembers; j++ {
			if !privKeys[i].Consistent(*privKeys[j]) {
				t.Fatalf("%s and %s have inconsistent keys after all rotations",
					memberNames[i], memberNames[j])
			}
		}
	}

	fmt.Println("✓ All members have consistent keys after multiple rotations")
	fmt.Println("✓ TreeKEM key rotation scenario completed successfully")
}

// TestTreeKEMWithMLSMessaging tests TreeKEM integration demonstrating group key management
// This test shows how TreeKEM enables secure group communication with member addition/removal
func TestTreeKEMWithMLSMessaging(t *testing.T) {
	fmt.Println("\n=== TreeKEM with MLS Group Key Management Test ===")

	suite := KYBER1024_AES256GCM_SHA512_DILITHIUM3
	numMembers := 5
	memberNames := []string{"Alice", "Bob", "Charlie", "Diana", "Eve"}

	// Step 1: Create TreeKEM group with post-quantum cryptography
	fmt.Printf("Creating TreeKEM group with %d members...\n", numMembers)
	pub := NewTreeKEMPublicKey(suite)
	members := make([]*TreeKEMPrivateKey, numMembers)
	sigKeys := make([]SignaturePrivateKey, numMembers)
	leafSecrets := make([][]byte, numMembers)

	for i := 0; i < numMembers; i++ {
		// Generate signature key pair
		sigScheme := suite.Scheme()
		sigKey, err := sigScheme.Generate()
		if err != nil {
			t.Fatalf("Failed to generate signature key for %s: %v", memberNames[i], err)
		}
		sigKeys[i] = sigKey

		// Generate leaf secret
		leafSecret := make([]byte, suite.Constants().SecretSize)
		_, err = rand.Read(leafSecret)
		if err != nil {
			t.Fatalf("Failed to generate leaf secret for %s: %v", memberNames[i], err)
		}
		leafSecrets[i] = leafSecret

		// Create key package
		cred := NewBasicCredential([]byte(memberNames[i]), suite.Scheme(), sigKey.PublicKey)
		keyPkg, err := NewKeyPackageWithSecret(suite, leafSecret, cred, sigKey)
		if err != nil {
			t.Fatalf("Failed to create key package for %s: %v", memberNames[i], err)
		}

		// Add to TreeKEM tree
		index := pub.AddLeaf(*keyPkg)
		members[i] = NewTreeKEMPrivateKey(suite, pub.Size(), index, leafSecret)

		// Update the public key to match the derived private key
		nodePriv, err := members[i].privateKey(toNodeIndex(index))
		if err != nil {
			t.Fatalf("Failed to get node private key for %s: %v", memberNames[i], err)
		}
		keyPkg.InitKey = nodePriv.PublicKey
		err = keyPkg.Sign(sigKey)
		if err != nil {
			t.Fatalf("Failed to re-sign key package for %s: %v", memberNames[i], err)
		}
		pub.UpdateLeaf(index, *keyPkg)

		fmt.Printf("✓ Added %s to TreeKEM group at index %d\n", memberNames[i], index)
	}

	fmt.Printf("✓ TreeKEM group created with %d members using post-quantum cryptography\n", numMembers)

	// Step 2: Initialize all members with a common group state
	fmt.Println("\n--- Test 1: Establishing Common Group State ---")

	// In TreeKEM, all members need to have the same initial group state
	// We'll simulate this by having Alice perform an initial key update that all members process
	fmt.Println("Alice establishes initial group state...")

	context := []byte("initial-group-setup")
	initialSecret := make([]byte, suite.Constants().SecretSize)
	_, err := rand.Read(initialSecret)
	if err != nil {
		t.Fatalf("Failed to generate initial group secret: %v", err)
	}

	// Alice performs initial Encap to establish group state
	aliceInitialPriv, initialPath, err := pub.Encap(LeafIndex(0), context, initialSecret, sigKeys[0], nil)
	if err != nil {
		t.Fatalf("Alice's initial group setup failed: %v", err)
	}
	fmt.Printf("✓ Alice established initial group state with %d path steps\n", len(initialPath.Steps))

	// All other members process Alice's initial setup
	for i := 1; i < numMembers; i++ {
		err = members[i].Decap(LeafIndex(0), *pub, context, *initialPath)
		if err != nil {
			t.Fatalf("%s failed to process initial group setup: %v", memberNames[i], err)
		}
		fmt.Printf("✓ %s processed initial group setup\n", memberNames[i])
	}

	// Update Alice's private key reference
	members[0] = aliceInitialPriv

	// Now verify all members have consistent TreeKEM keys
	fmt.Println("Verifying all members have consistent TreeKEM keys...")
	for i := 0; i < numMembers-1; i++ {
		for j := i + 1; j < numMembers; j++ {
			if !members[i].Consistent(*members[j]) {
				t.Fatalf("%s and %s have inconsistent TreeKEM keys", memberNames[i], memberNames[j])
			}
		}
	}
	fmt.Printf("✓ All %d members have consistent TreeKEM keys for secure messaging\n", numMembers)

	// Step 2.5: Test actual message encryption and decryption
	fmt.Println("\n--- Test 1.5: Message Encryption and Decryption ---")
	testMessage := []byte("Hello everyone! This is a secure message encrypted with TreeKEM-derived keys.")
	fmt.Printf("Original message: %s\n", string(testMessage))

	// Derive application keys from TreeKEM state for encryption
	// In a real MLS implementation, this would use the application secret derived from TreeKEM
	// For demonstration, we'll use a TreeKEM path secret as the basis for encryption

	// Get a shared secret from Alice's TreeKEM state (use the root path secret)
	rootNode := root(pub.Size())
	rootSecret, ok := members[0].PathSecrets[rootNode]
	if !ok {
		t.Fatalf("Alice doesn't have root path secret")
	}
	fmt.Printf("✓ Retrieved root path secret from TreeKEM (length: %d bytes)\n", len(rootSecret))

	// Derive an encryption key from the root secret using the cipher suite's key derivation
	keySize := suite.Constants().KeySize
	encryptionKey := suite.deriveAppSecret(rootSecret, "app-key", toNodeIndex(LeafIndex(0)), 0, keySize)
	fmt.Printf("✓ Derived application encryption key (length: %d bytes)\n", len(encryptionKey))

	// Create AEAD cipher for encryption
	aead, err := suite.NewAEAD(encryptionKey)
	if err != nil {
		t.Fatalf("Failed to create AEAD: %v", err)
	}

	// Encrypt the message using AES-256-GCM
	nonce := make([]byte, suite.Constants().NonceSize)
	_, err = rand.Read(nonce)
	if err != nil {
		t.Fatalf("Failed to generate nonce: %v", err)
	}

	ciphertext := aead.Seal(nil, nonce, testMessage, []byte("TreeKEM-MLS-AAD"))
	fmt.Printf("✓ Message encrypted (ciphertext length: %d bytes, nonce length: %d bytes)\n",
		len(ciphertext), len(nonce))

	// All members should be able to decrypt the message using their TreeKEM-derived keys
	fmt.Println("Testing message decryption by all members...")
	for i := 0; i < numMembers; i++ {
		// Each member derives the same encryption key from their TreeKEM state
		memberRootSecret, ok := members[i].PathSecrets[rootNode]
		if !ok {
			t.Fatalf("%s doesn't have root path secret", memberNames[i])
		}

		memberEncryptionKey := suite.deriveAppSecret(memberRootSecret, "app-key", toNodeIndex(LeafIndex(0)), 0, keySize)

		// Create AEAD cipher for decryption
		memberAead, err := suite.NewAEAD(memberEncryptionKey)
		if err != nil {
			t.Fatalf("%s failed to create AEAD: %v", memberNames[i], err)
		}

		// Decrypt the message
		plaintext, err := memberAead.Open(nil, nonce, ciphertext, []byte("TreeKEM-MLS-AAD"))
		if err != nil {
			t.Fatalf("%s failed to decrypt message: %v", memberNames[i], err)
		}

		// Verify the decrypted message matches the original
		if string(plaintext) != string(testMessage) {
			t.Fatalf("%s decrypted wrong message: got %s, expected %s",
				memberNames[i], string(plaintext), string(testMessage))
		}

		fmt.Printf("✓ %s successfully decrypted: %s\n", memberNames[i], string(plaintext))
	}

	// Step 3: Test TreeKEM key update operation
	fmt.Println("\n--- Test 2: TreeKEM Key Update Operations ---")
	updateContext := []byte("group-key-update")

	// Alice performs a key update
	newLeafSecret := make([]byte, suite.Constants().SecretSize)
	_, err = rand.Read(newLeafSecret)
	if err != nil {
		t.Fatalf("Failed to generate new leaf secret: %v", err)
	}

	aliceNewPriv, path, err := pub.Encap(LeafIndex(0), updateContext, newLeafSecret, sigKeys[0], nil)
	if err != nil {
		t.Fatalf("Alice's TreeKEM update failed: %v", err)
	}
	fmt.Printf("✓ Alice performed TreeKEM key update with %d path steps\n", len(path.Steps))

	// All other members process Alice's update
	for i := 1; i < numMembers; i++ {
		err = members[i].Decap(LeafIndex(0), *pub, updateContext, *path)
		if err != nil {
			t.Fatalf("%s failed to process Alice's TreeKEM update: %v", memberNames[i], err)
		}

		// Verify consistency
		if !aliceNewPriv.Consistent(*members[i]) {
			t.Fatalf("%s's TreeKEM key is not consistent with Alice's after update", memberNames[i])
		}

		fmt.Printf("✓ %s successfully processed Alice's TreeKEM update\n", memberNames[i])
	}

	// Update Alice's private key reference
	members[0] = aliceNewPriv

	// Step 4: Demonstrate member removal and forward secrecy
	fmt.Println("\n--- Test 3: Member Removal and Forward Secrecy ---")

	// Store Charlie and Diana's current states before removal
	charlieState := members[2].Clone()
	dianaState := members[3].Clone()

	fmt.Printf("Removing %s and %s from the group...\n", memberNames[2], memberNames[3])

	// Remove Charlie and Diana from the tree (indices 2 and 3)
	pub.BlankPath(LeafIndex(2))
	pub.BlankPath(LeafIndex(3))
	fmt.Printf("✓ Removed %s and %s from TreeKEM tree\n", memberNames[2], memberNames[3])

	// Alice performs another update after removal
	postRemovalSecret := make([]byte, suite.Constants().SecretSize)
	_, err = rand.Read(postRemovalSecret)
	if err != nil {
		t.Fatalf("Failed to generate post-removal leaf secret: %v", err)
	}

	alicePostRemovalPriv, postRemovalPath, err := pub.Encap(LeafIndex(0), updateContext, postRemovalSecret, sigKeys[0], nil)
	if err != nil {
		t.Fatalf("Alice's post-removal TreeKEM update failed: %v", err)
	}
	fmt.Printf("✓ Alice performed TreeKEM update after member removal (%d path steps)\n", len(postRemovalPath.Steps))

	// Remaining members (Bob and Eve) should be able to process the update
	remainingIndices := []int{1, 4} // Bob and Eve
	for _, i := range remainingIndices {
		err = members[i].Decap(LeafIndex(0), *pub, updateContext, *postRemovalPath)
		if err != nil {
			t.Fatalf("%s failed to process Alice's update after member removal: %v", memberNames[i], err)
		}

		// Verify consistency
		if !alicePostRemovalPriv.Consistent(*members[i]) {
			t.Fatalf("%s's TreeKEM key is not consistent with Alice's after removal", memberNames[i])
		}

		fmt.Printf("✓ %s successfully processed Alice's update after member removal\n", memberNames[i])
	}

	// Removed members should NOT be able to process the update (forward secrecy)
	fmt.Println("Testing forward secrecy...")

	err = charlieState.Decap(LeafIndex(0), *pub, updateContext, *postRemovalPath)
	if err == nil {
		t.Fatal("Charlie should not be able to process updates after removal (forward secrecy violation)")
	}
	fmt.Printf("✓ Charlie correctly cannot process updates after removal (forward secrecy)\n")

	err = dianaState.Decap(LeafIndex(0), *pub, updateContext, *postRemovalPath)
	if err == nil {
		t.Fatal("Diana should not be able to process updates after removal (forward secrecy violation)")
	}
	fmt.Printf("✓ Diana correctly cannot process updates after removal (forward secrecy)\n")

	// Step 4.5: Test message encryption/decryption after member removal
	fmt.Println("\n--- Test 3.5: Message Encryption After Member Removal ---")
	postRemovalMessage := []byte("This secret message should only be readable by Alice, Bob, and Eve!")
	fmt.Printf("Post-removal message: %s\n", string(postRemovalMessage))

	// Derive new encryption key from Alice's post-removal TreeKEM state
	postRemovalRootSecret, ok := alicePostRemovalPriv.PathSecrets[rootNode]
	if !ok {
		t.Fatalf("Alice doesn't have root path secret after removal")
	}

	postRemovalEncryptionKey := suite.deriveAppSecret(postRemovalRootSecret, "app-key-post-removal", toNodeIndex(LeafIndex(0)), 1, keySize)
	fmt.Printf("✓ Derived new encryption key after member removal (length: %d bytes)\n", len(postRemovalEncryptionKey))

	// Create AEAD cipher for post-removal encryption
	postRemovalAead, err := suite.NewAEAD(postRemovalEncryptionKey)
	if err != nil {
		t.Fatalf("Failed to create post-removal AEAD: %v", err)
	}

	// Encrypt the post-removal message
	postRemovalNonce := make([]byte, suite.Constants().NonceSize)
	_, err = rand.Read(postRemovalNonce)
	if err != nil {
		t.Fatalf("Failed to generate post-removal nonce: %v", err)
	}

	postRemovalCiphertext := postRemovalAead.Seal(nil, postRemovalNonce, postRemovalMessage, []byte("TreeKEM-MLS-AAD-PostRemoval"))
	fmt.Printf("✓ Post-removal message encrypted (ciphertext length: %d bytes)\n", len(postRemovalCiphertext))

	// Remaining members (Alice, Bob, Eve) should be able to decrypt
	fmt.Println("Testing decryption by remaining members...")
	remainingIndices = []int{0, 1, 4} // Alice, Bob, Eve
	for _, i := range remainingIndices {
		// Get the member's current TreeKEM state (updated after removal)
		var memberState *TreeKEMPrivateKey
		if i == 0 {
			memberState = alicePostRemovalPriv
		} else {
			memberState = members[i]
		}

		// Derive encryption key from member's current state
		memberPostRemovalRootSecret, ok := memberState.PathSecrets[rootNode]
		if !ok {
			t.Fatalf("%s doesn't have root path secret after removal", memberNames[i])
		}

		memberPostRemovalEncryptionKey := suite.deriveAppSecret(memberPostRemovalRootSecret, "app-key-post-removal", toNodeIndex(LeafIndex(0)), 1, keySize)

		// Create AEAD cipher for decryption
		memberPostRemovalAead, err := suite.NewAEAD(memberPostRemovalEncryptionKey)
		if err != nil {
			t.Fatalf("%s failed to create post-removal AEAD: %v", memberNames[i], err)
		}

		// Decrypt the message
		plaintext, err := memberPostRemovalAead.Open(nil, postRemovalNonce, postRemovalCiphertext, []byte("TreeKEM-MLS-AAD-PostRemoval"))
		if err != nil {
			t.Fatalf("%s failed to decrypt post-removal message: %v", memberNames[i], err)
		}

		// Verify the decrypted message matches the original
		if string(plaintext) != string(postRemovalMessage) {
			t.Fatalf("%s decrypted wrong post-removal message: got %s, expected %s",
				memberNames[i], string(plaintext), string(postRemovalMessage))
		}

		fmt.Printf("✓ %s successfully decrypted post-removal message: %s\n", memberNames[i], string(plaintext))
	}

	// Removed members should NOT be able to decrypt the new message (forward secrecy)
	fmt.Println("Testing that removed members cannot decrypt post-removal messages...")

	// Charlie tries to decrypt with his old key (should fail)
	charlieOldRootSecret, ok := charlieState.PathSecrets[rootNode]
	if !ok {
		t.Fatalf("Charlie doesn't have root path secret")
	}

	charlieOldEncryptionKey := suite.deriveAppSecret(charlieOldRootSecret, "app-key-post-removal", toNodeIndex(LeafIndex(0)), 1, keySize)
	charlieOldAead, err := suite.NewAEAD(charlieOldEncryptionKey)
	if err != nil {
		t.Fatalf("Charlie failed to create old AEAD: %v", err)
	}

	_, err = charlieOldAead.Open(nil, postRemovalNonce, postRemovalCiphertext, []byte("TreeKEM-MLS-AAD-PostRemoval"))
	if err == nil {
		t.Fatal("Charlie should not be able to decrypt post-removal message (forward secrecy violation)")
	}
	fmt.Printf("✓ Charlie correctly cannot decrypt post-removal message (forward secrecy)\n")

	// Diana tries to decrypt with her old key (should fail)
	dianaOldRootSecret, ok := dianaState.PathSecrets[rootNode]
	if !ok {
		t.Fatalf("Diana doesn't have root path secret")
	}

	dianaOldEncryptionKey := suite.deriveAppSecret(dianaOldRootSecret, "app-key-post-removal", toNodeIndex(LeafIndex(0)), 1, keySize)
	dianaOldAead, err := suite.NewAEAD(dianaOldEncryptionKey)
	if err != nil {
		t.Fatalf("Diana failed to create old AEAD: %v", err)
	}

	_, err = dianaOldAead.Open(nil, postRemovalNonce, postRemovalCiphertext, []byte("TreeKEM-MLS-AAD-PostRemoval"))
	if err == nil {
		t.Fatal("Diana should not be able to decrypt post-removal message (forward secrecy violation)")
	}
	fmt.Printf("✓ Diana correctly cannot decrypt post-removal message (forward secrecy)\n")

	// Step 5: Demonstrate that the remaining members can continue to communicate
	fmt.Println("\n--- Test 4: Continued Group Communication ---")
	fmt.Println("Verifying remaining members can continue secure communication...")

	// Bob performs another update to show the group is still functional
	bobUpdateSecret := make([]byte, suite.Constants().SecretSize)
	_, err = rand.Read(bobUpdateSecret)
	if err != nil {
		t.Fatalf("Failed to generate Bob's update secret: %v", err)
	}

	bobNewPriv, bobPath, err := pub.Encap(LeafIndex(1), updateContext, bobUpdateSecret, sigKeys[1], nil)
	if err != nil {
		t.Fatalf("Bob's TreeKEM update failed: %v", err)
	}
	fmt.Printf("✓ Bob performed TreeKEM update (%d path steps)\n", len(bobPath.Steps))

	// Alice and Eve should be able to process Bob's update
	err = alicePostRemovalPriv.Decap(LeafIndex(1), *pub, updateContext, *bobPath)
	if err != nil {
		t.Fatalf("Alice failed to process Bob's update: %v", err)
	}
	fmt.Printf("✓ Alice successfully processed Bob's update\n")

	err = members[4].Decap(LeafIndex(1), *pub, updateContext, *bobPath)
	if err != nil {
		t.Fatalf("Eve failed to process Bob's update: %v", err)
	}
	fmt.Printf("✓ Eve successfully processed Bob's update\n")

	// Verify all remaining members have consistent keys
	members[0] = alicePostRemovalPriv
	members[1] = bobNewPriv
	if !members[0].Consistent(*members[1]) || !members[1].Consistent(*members[4]) {
		t.Fatal("Remaining members have inconsistent keys after Bob's update")
	}
	fmt.Printf("✓ All remaining members have consistent TreeKEM keys\n")

	// Step 5.5: Final message encryption test after all updates
	fmt.Println("\n--- Test 4.5: Final Message Encryption After All Updates ---")
	finalMessage := []byte("Final secure message after all TreeKEM updates and member changes!")
	fmt.Printf("Final message: %s\n", string(finalMessage))

	// Use Bob's updated state to encrypt the final message
	finalRootSecret, ok := bobNewPriv.PathSecrets[rootNode]
	if !ok {
		t.Fatalf("Bob doesn't have root path secret after final update")
	}

	finalEncryptionKey := suite.deriveAppSecret(finalRootSecret, "app-key-final", toNodeIndex(LeafIndex(1)), 2, keySize)

	// Create AEAD cipher for final encryption
	finalAead, err := suite.NewAEAD(finalEncryptionKey)
	if err != nil {
		t.Fatalf("Failed to create final AEAD: %v", err)
	}

	// Encrypt the final message
	finalNonce := make([]byte, suite.Constants().NonceSize)
	_, err = rand.Read(finalNonce)
	if err != nil {
		t.Fatalf("Failed to generate final nonce: %v", err)
	}

	finalCiphertext := finalAead.Seal(nil, finalNonce, finalMessage, []byte("TreeKEM-MLS-AAD-Final"))
	fmt.Printf("✓ Final message encrypted (ciphertext length: %d bytes)\n", len(finalCiphertext))

	// All remaining members should be able to decrypt the final message
	fmt.Println("Testing final message decryption by all remaining members...")
	finalRemainingMembers := []*TreeKEMPrivateKey{members[0], bobNewPriv, members[4]}
	finalRemainingNames := []string{memberNames[0], memberNames[1], memberNames[4]}

	for i, memberState := range finalRemainingMembers {
		// Derive encryption key from member's final state
		memberFinalRootSecret, ok := memberState.PathSecrets[rootNode]
		if !ok {
			t.Fatalf("%s doesn't have root path secret for final decryption", finalRemainingNames[i])
		}

		memberFinalEncryptionKey := suite.deriveAppSecret(memberFinalRootSecret, "app-key-final", toNodeIndex(LeafIndex(1)), 2, keySize)

		// Create AEAD cipher for final decryption
		memberFinalAead, err := suite.NewAEAD(memberFinalEncryptionKey)
		if err != nil {
			t.Fatalf("%s failed to create final AEAD: %v", finalRemainingNames[i], err)
		}

		// Decrypt the final message
		plaintext, err := memberFinalAead.Open(nil, finalNonce, finalCiphertext, []byte("TreeKEM-MLS-AAD-Final"))
		if err != nil {
			t.Fatalf("%s failed to decrypt final message: %v", finalRemainingNames[i], err)
		}

		// Verify the decrypted message matches the original
		if string(plaintext) != string(finalMessage) {
			t.Fatalf("%s decrypted wrong final message: got %s, expected %s",
				finalRemainingNames[i], string(plaintext), string(finalMessage))
		}

		fmt.Printf("✓ %s successfully decrypted final message: %s\n", finalRemainingNames[i], string(plaintext))
	}

	fmt.Println("\n=== TreeKEM with MLS Group Key Management Test Completed Successfully! ===")
	fmt.Println("✓ Group creation with post-quantum cryptography (Kyber1024 + Dilithium3)")
	fmt.Printf("✓ %d members added to TreeKEM group\n", numMembers)
	fmt.Println("✓ TreeKEM key consistency verification across all members")
	fmt.Println("✓ Message encryption/decryption using TreeKEM-derived keys (AES-256-GCM)")
	fmt.Println("✓ All members can decrypt messages encrypted with shared TreeKEM keys")
	fmt.Println("✓ TreeKEM key update operations with path propagation")
	fmt.Println("✓ Member removal from TreeKEM tree (2 members removed)")
	fmt.Println("✓ Forward secrecy verification (removed members cannot process new updates)")
	fmt.Println("✓ Message encryption forward secrecy (removed members cannot decrypt new messages)")
	fmt.Println("✓ Continued group communication and messaging after member removal")
	fmt.Println("✓ Multiple message encryption/decryption cycles with key updates")
	fmt.Println("✓ Complete TreeKEM integration with post-quantum MLS cryptography and messaging")
}
