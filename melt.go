// Package melt provides function to create a mnemonic set of keys from a
// ed25519 private key, and restore that key from the same mnemonic set of
// words.
package melt

import (
	"crypto/ed25519"
	"fmt"

	"github.com/tyler-smith/go-bip39"
)

// ToMnemonic takes a ed25519 private key and returns the list of words.
func ToMnemonic(key *ed25519.PrivateKey) (string, error) {
	words, err := bip39.NewMnemonic(key.Seed())
	if err != nil {
		return "", fmt.Errorf("could not create a mnemonic set of words: %w", err)
	}

	return words, nil
}

// FromMnemonic takes a mnemonic list of words and returns an ed25519
// private key.
func FromMnemonic(mnemonic string) (ed25519.PrivateKey, error) {
	seed, err := bip39.EntropyFromMnemonic(mnemonic)
	if err != nil {
		return nil, fmt.Errorf("failed to get seed from mnemonic: %w", err)
	}
	return ed25519.NewKeyFromSeed(seed), nil
}
