package melt

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/mikesmitty/edkey"
	"github.com/tyler-smith/go-bip39"
	"golang.org/x/crypto/ssh"
)

func Backup(path string) (string, string, error) {
	bts, err := os.ReadFile(path)
	if err != nil {
		return "", "", fmt.Errorf("could not read key: %w", err)
	}

	key, err := ssh.ParseRawPrivateKey(bts)
	if err != nil {
		return "", "", fmt.Errorf("could not parse key: %w", err)
	}

	var seed []byte
	switch key := key.(type) {
	case *ed25519.PrivateKey:
		seed = key.Seed()
	default:
		return "", "", fmt.Errorf("unknown key type: %v", key)
	}

	words, err := bip39.NewMnemonic(seed)
	if err != nil {
		return "", "", fmt.Errorf("could not create a mnemonic for %s: %w", path, err)
	}

	sum, err := sha256sum(bts)
	return words, sum, err
}

func Restore(path, mnemonic, keyType string) (string, error) {
	seed, err := bip39.EntropyFromMnemonic(mnemonic)
	if err != nil {
		return "", err
	}

	var bts []byte
	var pubkey ssh.PublicKey

	switch keyType {
	case "ed25519":
		pvtKey := ed25519.NewKeyFromSeed(seed)
		bts = pem.EncodeToMemory(&pem.Block{
			Type:  "OPENSSH PRIVATE KEY",
			Bytes: edkey.MarshalED25519PrivateKey(pvtKey),
		})
		pubkey, err = ssh.NewPublicKey(pvtKey.Public())
		if err != nil {
			return "", fmt.Errorf("could not prepare public key: %w", err)
		}
	default:
		return "", fmt.Errorf("unsupported key type: %q", keyType)
	}

	if err := os.WriteFile(path, bts, 0o600); err != nil {
		return "", fmt.Errorf("failed to write private key: %w", err)
	}

	if err := os.WriteFile(path+".pub", ssh.MarshalAuthorizedKey(pubkey), 0o655); err != nil {
		return "", fmt.Errorf("failed to write public key: %w", err)
	}

	return sha256sum(bts)
}

func sha256sum(bts []byte) (string, error) {
	digest := sha256.New()
	if _, err := digest.Write(bts); err != nil {
		return "", fmt.Errorf("failed to sha256sum key: %w", err)
	}
	return hex.EncodeToString(digest.Sum(nil)), nil
}
