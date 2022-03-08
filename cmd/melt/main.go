package main

import (
	"crypto/ed25519"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/caarlos0/sshmarshal"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/melt"
	"github.com/mattn/go-isatty"
	"github.com/muesli/coral"
	mcoral "github.com/muesli/mango-coral"
	"github.com/muesli/roff"
	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

var (
	headerStyle   = lipgloss.NewStyle().Italic(true)
	mnemonicStyle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("63")).Margin(1).Width(60)
	restoreStyle  = lipgloss.NewStyle().Bold(true).Margin(1)

	rootCmd = &coral.Command{
		Use: "melt",
		Example: `  melt ~/.ssh/id_ed25519
  melt ~/.ssh/id_ed25519 > mnemonic
  melt restore --mnemonic \"list of words\" ./restored_id25519
  melt restore ./restored_id25519 < mnemonic`,
		Short: "Backup a SSH private key to a mnemonic set of keys",
		Long: `melt uses bip39 to create a mnemonic set of words that represents your SSH keys.

You can then use those words to restore your private key at any time.`,
		Args:         coral.ExactArgs(1),
		SilenceUsage: true,
		RunE: func(cmd *coral.Command, args []string) error {
			mnemonic, err := backup(args[0], nil)
			if err != nil {
				return err
			}
			if isatty.IsTerminal(os.Stdout.Fd()) {
				fmt.Println(headerStyle.Render(`Success!!!

You can now use the words bellow to recreate your key using the 'keys restore' command.
Store them somewhere safe, print or memorize them.`))
				fmt.Println(mnemonicStyle.Render(mnemonic))
			} else {
				fmt.Print(mnemonic)
			}
			return nil
		},
	}

	mnemonic   string
	restoreCmd = &coral.Command{
		Use:   "restore",
		Short: "Recreate a key using the given mnemonic words",
		Example: `  melt restore --mnemonic \"list of words\" ./restored_id25519
  melt restore ./restored_id25519 < mnemonic`,
		Aliases: []string{"res", "r"},
		Args:    coral.ExactArgs(1),
		RunE: func(cmd *coral.Command, args []string) error {
			if err := restore(maybeFile(mnemonic), args[0]); err != nil {
				return err
			}

			fmt.Println(restoreStyle.Render(fmt.Sprintf(`Successfully restored keys to '%[1]s' and '%[1]s.pub'!`, args[0])))
			return nil
		},
	}

	manCmd = &coral.Command{
		Use:          "man",
		Args:         coral.NoArgs,
		Short:        "generate man pages",
		Hidden:       true,
		SilenceUsage: true,
		RunE: func(cmd *coral.Command, args []string) error {
			manPage, err := mcoral.NewManPage(1, rootCmd)
			if err != nil {
				return err
			}
			manPage = manPage.WithSection("Copyright", "(C) 2022 Charmbracelet, Inc.\n"+
				"Released under MIT license.")
			fmt.Println(manPage.Build(roff.NewDocument()))
			return nil
		},
	}
)

func init() {
	rootCmd.AddCommand(restoreCmd, manCmd)

	restoreCmd.PersistentFlags().StringVarP(&mnemonic, "mnemonic", "m", "-", "Mnemonic set of words given by the backup command")
	_ = restoreCmd.MarkFlagRequired("mnemonic")
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func maybeFile(s string) string {
	if s == "-" {
		bts, err := io.ReadAll(os.Stdin)
		if err == nil {
			return string(bts)
		}
	}
	bts, err := os.ReadFile(s)
	if err != nil {
		return s
	}
	return string(bts)
}

func backup(path string, pwd []byte) (string, error) {
	bts, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("could not read key: %w", err)
	}

	var key interface{}
	if pwd == nil {
		key, err = ssh.ParseRawPrivateKey(bts)
	} else {
		key, err = ssh.ParseRawPrivateKeyWithPassphrase(bts, pwd)
	}
	if err != nil {
		pwderr := &ssh.PassphraseMissingError{}
		if errors.As(err, &pwderr) {
			fmt.Fprintf(os.Stderr, "Enter the password to decrypt %q: ", path)
			pwd, err := term.ReadPassword(int(os.Stdin.Fd()))
			fmt.Printf("\n\n")
			if err != nil {
				return "", fmt.Errorf("could not read password for key: %w", err)
			}
			return backup(path, pwd)
		}
		return "", fmt.Errorf("could not parse key: %w", err)
	}

	switch key := key.(type) {
	case *ed25519.PrivateKey:
		return melt.ToMnemonic(key)
	default:
		return "", fmt.Errorf("unknown key type: %v", key)
	}
}

func restore(mnemonic, path string) error {
	pvtKey, err := melt.FromMnemonic(mnemonic)
	if err != nil {
		return err
	}
	block, err := sshmarshal.MarshalPrivateKey(pvtKey, "")
	if err != nil {
		return fmt.Errorf("could not marshal private key: %w", err)
	}
	bts := pem.EncodeToMemory(block)
	pubkey, err := ssh.NewPublicKey(pvtKey.Public())
	if err != nil {
		return fmt.Errorf("could not prepare public key: %w", err)
	}

	if err := os.WriteFile(path, bts, 0o600); err != nil {
		return fmt.Errorf("failed to write private key: %w", err)
	}

	if err := os.WriteFile(path+".pub", ssh.MarshalAuthorizedKey(pubkey), 0o600); err != nil {
		return fmt.Errorf("failed to write public key: %w", err)
	}
	return nil
}
