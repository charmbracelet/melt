package melt

import (
	"crypto/ed25519"
	"fmt"

	"github.com/tyler-smith/go-bip39"
)

func ToMnemonic(key *ed25519.PrivateKey) (string, error) {
	words, err := bip39.NewMnemonic(key.Seed())
	if err != nil {
		return "", fmt.Errorf("could not create a mnemonics: %w", err)
	}

	return words, nil
}

func FromMnemonic(mnemonic string) (ed25519.PrivateKey, error) {
	seed, err := bip39.EntropyFromMnemonic(mnemonic)
	if err != nil {
		return nil, fmt.Errorf("failed to get seed from mnemonic: %w", err)
	}
	return ed25519.NewKeyFromSeed(seed), nil
}
