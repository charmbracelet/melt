package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/charmbracelet/lipgloss"
	"github.com/mikesmitty/edkey"
	"github.com/muesli/coral"
	"github.com/tyler-smith/go-bip39"
	"golang.org/x/crypto/ssh"
)

var (
	headerStyle   = lipgloss.NewStyle().Align(lipgloss.Center).Italic(true)
	mnemonicStyle = lipgloss.NewStyle().Align(lipgloss.Center).Bold(true).Foreground(lipgloss.Color("63")).Margin(1).Width(60)
	restoreStyle  = lipgloss.NewStyle().Bold(true).Margin(1)

	rootCmd = &coral.Command{
		Use:          "keys",
		Short:        "Backup and restore SSH keys using a mnemonic",
		SilenceUsage: true,
	}
	keypath   string
	backupCmd = &coral.Command{
		Use:   "backup",
		Short: "Backup a SSH private key",
		RunE: func(cmd *coral.Command, args []string) error {
			words, sum, err := backup(keypath)
			if err != nil {
				return err
			}
			fmt.Println(headerStyle.Render(fmt.Sprintf(`Success!
You can now use the words bellow to recreate your key using the 'keys restore' command.
Store them somewhere safe, print or memorize them.

For the record, the original key sha256sum is %s`, sum)))
			fmt.Println(mnemonicStyle.Render(words))

			return nil
		},
	}

	words      string
	algo       string
	restoreCmd = &coral.Command{
		Use:   "restore",
		Short: "Recreate a key using the given mnemonic words",
		RunE: func(cmd *coral.Command, args []string) error {
			sum, err := restore(keypath, words, algo)
			if err != nil {
				return err
			}

			fmt.Println(restoreStyle.Render(fmt.Sprintf(`Restored keys to %s and %[1]s.pub.
sha256sum is %s`, keypath, sum)),
			)
			return nil
		},
	}
)

func init() {
	rootCmd.AddCommand(backupCmd, restoreCmd)

	backupCmd.PersistentFlags().StringVarP(&keypath, "key", "k", "", "Path to the key you want to backup")
	_ = backupCmd.MarkFlagRequired("key")

	restoreCmd.PersistentFlags().StringVarP(&keypath, "key", "k", "", "Path to where you want to save the key")
	restoreCmd.PersistentFlags().StringVarP(&words, "words", "w", "", "Mnemonic words given by the backup command")
	restoreCmd.PersistentFlags().StringVarP(&algo, "algo", "a", "ed25519", "Key algorithm")
	_ = restoreCmd.MarkFlagRequired("key")
	_ = restoreCmd.MarkFlagRequired("words")
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func backup(path string) (string, string, error) {
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

func restore(path, mnemonic, keyType string) (string, error) {
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
