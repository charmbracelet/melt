package main

import (
	"crypto/ed25519"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"

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

const (
	maxWidth    = 72
	cmdMaxWidth = 40
)

var (
	widthOnce      sync.Once
	terminalWidth  int
	docStyle       = lipgloss.NewStyle().Margin(1, 2)
	baseStyle      = lipgloss.NewStyle().Margin(0, 0, 1, 2)
	headerStyle    = lipgloss.NewStyle()
	lineStyle      = lipgloss.NewStyle().Foreground(lipgloss.AdaptiveColor{Light: "", Dark: "237"})
	backslashStyle = lipgloss.NewStyle().Foreground(lipgloss.AdaptiveColor{Light: "", Dark: "239"})
	mnemonicStyle  = baseStyle.Copy().
			Foreground(lipgloss.Color("204")).
			Background(lipgloss.Color("234")).
			Padding(1, 2)
	cmdStyle     = baseStyle.Copy()
	restoreStyle = lipgloss.NewStyle().Bold(true).Margin(1)
	keyStyle     = lipgloss.NewStyle().Foreground(lipgloss.AdaptiveColor{Light: "", Dark: "36"})

	rootCmd = &coral.Command{
		Use: "melt",
		Example: `  melt ~/.ssh/id_ed25519
  melt ~/.ssh/id_ed25519 > seed
  melt restore --seed "list of words" ./restored_id25519
  melt restore ./restored_id25519 < seed`,
		Short: "Backup a SSH private key to a set of seed words",
		Long: `melt uses bip39 to create a set of seed words that can be used to rebuild your SSH keys.

You can use that seed to restore your public and private keys.`,
		Args:         coral.ExactArgs(1),
		SilenceUsage: true,
		RunE: func(cmd *coral.Command, args []string) error {
			mnemonic, err := backup(args[0], nil)
			if err != nil {
				return err
			}
			if isatty.IsTerminal(os.Stdout.Fd()) {
				b := strings.Builder{}
				w := getWidth(maxWidth)

				b.WriteRune('\n')
				header := headerStyle.Render("Success! ")
				headerGap := w - lipgloss.Width(header)
				line := lineStyle.Render(strings.Repeat("─", headerGap))
				renderBlock(&b, baseStyle, w, header+line)

				renderBlock(&b, baseStyle, w, "Your key has been melted down to the seed words below. Store them somewhere safe. You can use melt to recover your key at any time.")
				renderBlock(&b, mnemonicStyle, w, mnemonic)
				renderBlock(&b, baseStyle, w, "To recreate this key run:")

				// Restore command
				cmdEOL := backslashStyle.Render(" \\")
				const cmdIndent = 4
				cmd := cmdStyle.Copy().
					Width(w - lipgloss.Width(cmdEOL) - cmdIndent - 4).
					Render(os.Args[0] + " restore ./key --seed \"" + mnemonic + "\"")
				cmdLines := strings.Split(cmd, "\n")
				for i, l := range cmdLines {
					if i > 0 {
						b.WriteString(strings.Repeat(" ", cmdIndent))
					}
					b.WriteString(strings.TrimRight(l, " "))
					if i < len(cmdLines)-2 {
						b.WriteString(cmdEOL)
						b.WriteRune('\n')
					}
				}
				b.WriteRune('\n')

				fmt.Println(b.String())
			} else {
				fmt.Print(mnemonic)
			}
			return nil
		},
	}

	mnemonic   string
	restoreCmd = &coral.Command{
		Use:   "restore",
		Short: "Recreate a key using the given seed words",
		Example: `  melt restore --seed \"list of words\" ./restored_id25519
  melt restore ./restored_id25519 < seed`,
		Aliases: []string{"res", "r"},
		Args:    coral.ExactArgs(1),
		RunE: func(cmd *coral.Command, args []string) error {
			if err := restore(maybeFile(mnemonic), args[0]); err != nil {
				return err
			}

			pub := keyStyle.Render(args[0])
			priv := keyStyle.Render(args[0] + ".pub")
			fmt.Println(baseStyle.Render(fmt.Sprintf("\nSuccessfully restored keys to %s and %s!", pub, priv)))
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

	restoreCmd.PersistentFlags().StringVarP(&mnemonic, "seed", "s", "-", "Seed words")
	_ = restoreCmd.MarkFlagRequired("seed")
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

func getWidth(max int) int {
	var err error
	widthOnce.Do(func() {
		terminalWidth, _, err = term.GetSize(int(os.Stdout.Fd()))
	})
	if err != nil || terminalWidth > maxWidth {
		return maxWidth
	}
	return terminalWidth
}

func renderBlock(w io.Writer, s lipgloss.Style, width int, str string) {
	io.WriteString(w, s.Copy().Width(width).Render(str))
	io.WriteString(w, "\n")
}
