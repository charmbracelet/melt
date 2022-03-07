package main

import (
	"crypto/ed25519"
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
			bts, err := os.ReadFile(keypath)
			if err != nil {
				return fmt.Errorf("could not read key: %w", err)
			}

			key, err := ssh.ParseRawPrivateKey(bts)
			if err != nil {
				return fmt.Errorf("could not parse key: %w", err)
			}

			var seed []byte
			switch key := key.(type) {
			case *ed25519.PrivateKey:
				seed = key.Seed()
			default:
				return fmt.Errorf("unknown key type: %v", key)
			}

			words, err := bip39.NewMnemonic(seed)
			if err != nil {
				return fmt.Errorf("could not create a mnemonic for %s: %w", keypath, err)
			}

			fmt.Println(
				lipgloss.NewStyle().
					Align(lipgloss.Center).
					Italic(true).
					Render(`Success!
You can now use the words bellow to recreate your key usint the 'keys restore' command.
Store them somewhere safe, print or memorize them.`),
			)
			fmt.Println(
				lipgloss.NewStyle().
					Align(lipgloss.Center).
					Bold(true).
					Foreground(lipgloss.Color("63")).
					Margin(1).
					Width(60).
					Render(words),
			)

			return nil
		},
	}

	words      string
	restoreCmd = &coral.Command{
		Use:   "restore",
		Short: "Recreate a key using the given mnemonic words",
		RunE: func(cmd *coral.Command, args []string) error {
			seed, err := bip39.EntropyFromMnemonic(words)
			if err != nil {
				return err
			}

			pvtKey := ed25519.NewKeyFromSeed(seed)
			if err := os.WriteFile(
				keypath,
				pem.EncodeToMemory(&pem.Block{
					Type:  "OPENSSH PRIVATE KEY",
					Bytes: edkey.MarshalED25519PrivateKey(pvtKey),
				}),
				0o600,
			); err != nil {
				return fmt.Errorf("failed to write private key: %w", err)
			}

			pubKey, err := ssh.NewPublicKey(pvtKey.Public())
			if err != nil {
				return fmt.Errorf("could not prepare public key: %w", err)
			}

			if err := os.WriteFile(
				keypath+".pub",
				ssh.MarshalAuthorizedKey(pubKey),
				0o655,
			); err != nil {
				return fmt.Errorf("failed to write public key: %w", err)
			}

			fmt.Println(lipgloss.NewStyle().Bold(true).Render(fmt.Sprintf("Written keys to %s and %[1]s.pub", keypath)))

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
	_ = restoreCmd.MarkFlagRequired("key")
	_ = restoreCmd.MarkFlagRequired("words")
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	// srcPem, err := os.ReadFile("test_ed25519")
	// if err != nil {
	// 	log.Fatalln(err)
	// }
	//
	// srcKey, err := ssh.ParseRawPrivateKey(srcPem)
	// if err != nil {
	// 	log.Fatalln(err)
	// }
	//
	// words, err := bip39.NewMnemonic((srcKey.(*ed25519.PrivateKey)).Seed())
	// if err != nil {
	// 	log.Fatalln(err)
	// }
	// log.Println("words:", words)
	//
	// recovSeed, err := bip39.EntropyFromMnemonic(words)
	// if err != nil {
	// 	log.Fatalln(err)
	// }
	//
	// recovKey := ed25519.NewKeyFromSeed(recovSeed)
	// recovPem := pem.EncodeToMemory(&pem.Block{
	// 	Type:  "OPENSSH PRIVATE KEY",
	// 	Bytes: edkey.MarshalED25519PrivateKey(recovKey),
	// })
	//
	// log.Println("keys match?", string(recovPem) == string(srcPem))
}
