package main

import (
	"silvertiger.com/go/client/poc"
)

func main() {
	// Run cryptography demonstrations
	poc.RunCryptographyDemo()

	// Run file encryption demonstration
	poc.RunFileEncryptionDemo()

	// Run MLS group chat demonstration
	poc.RunMLSDemo()
}
