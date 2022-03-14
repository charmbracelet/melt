package main

import (
	"crypto/ed25519"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/caarlos0/sshmarshal"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/melt"
	"github.com/mattn/go-isatty"
	"github.com/muesli/coral"
	mcoral "github.com/muesli/mango-coral"
	"github.com/muesli/reflow/wordwrap"
	"github.com/muesli/roff"
	"github.com/muesli/termenv"
	"github.com/tyler-smith/go-bip39"
	"github.com/tyler-smith/go-bip39/wordlists"
	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

const (
	maxWidth = 72
)

var (
	baseStyle = lipgloss.NewStyle().Margin(0, 0, 1, 2)
	violet    = lipgloss.Color(completeColor("#6B50FF", "63", "12"))
	cmdStyle  = lipgloss.NewStyle().
			Foreground(lipgloss.AdaptiveColor{Light: "#FF5E8E", Dark: "#FF5E8E"}).
			Background(lipgloss.AdaptiveColor{Light: completeColor("#ECECEC", "255", "7"), Dark: "#1F1F1F"}).
			Padding(0, 1)
	mnemonicStyle = baseStyle.Copy().
			Foreground(violet).
			Background(lipgloss.AdaptiveColor{Light: completeColor("#EEEBFF", "255", "7"), Dark: completeColor("#1B1731", "235", "8")}).
			Padding(1, 2)
	keyPathStyle = lipgloss.NewStyle().Foreground(violet)

	mnemonic string
	language string

	rootCmd = &coral.Command{
		Use: "melt",
		Example: `  melt ~/.ssh/id_ed25519
  melt ~/.ssh/id_ed25519 > seed
  melt restore --seed "seed phrase" ./restored_id25519
  melt restore ./restored_id25519 < seed`,
		Short: "Generate a seed phrase from an SSH key",
		Long: `melt generates a seed phrase from an SSH key. That phrase can
be used to rebuild your public and private keys.`,
		Args:         coral.ExactArgs(1),
		SilenceUsage: true,
		RunE: func(cmd *coral.Command, args []string) error {
			if err := setLanguage(language); err != nil {
				return err
			}

			mnemonic, err := backup(args[0], nil)
			if err != nil {
				return err
			}
			if isatty.IsTerminal(os.Stdout.Fd()) {
				b := strings.Builder{}
				w := getWidth(maxWidth)

				b.WriteRune('\n')
				meltCmd := cmdStyle.Render(os.Args[0])
				renderBlock(&b, baseStyle, w, fmt.Sprintf("OK! Your key has been melted down to the seed phrase below. Store it somewhere safe. You can use %s to recover your key at any time.", meltCmd))
				renderBlock(&b, mnemonicStyle, w, mnemonic)
				renderBlock(&b, baseStyle, w, "To recreate this key run:")

				// Build formatted restore command
				const cmdEOL = " \\"
				var lang string
				if language != "en" {
					lang = fmt.Sprintf(" --language %s", language)
				}
				cmd := wordwrap.String(
					os.Args[0]+` restore`+lang+` ./my-key --seed "`+mnemonic+`"`,
					w-lipgloss.Width(cmdEOL)-baseStyle.GetHorizontalFrameSize()*2,
				)
				leftPad := strings.Repeat(" ", baseStyle.GetMarginLeft())
				cmdLines := strings.Split(cmd, "\n")
				for i, l := range cmdLines {
					b.WriteString(leftPad)
					b.WriteString(l)
					if i < len(cmdLines)-1 {
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

	restoreCmd = &coral.Command{
		Use:   "restore",
		Short: "Recreate a key using the given seed phrase",
		Example: `  melt restore --seed "seed phrase" ./restored_id25519
  melt restore ./restored_id25519 < seed`,
		Aliases: []string{"res", "r"},
		Args:    coral.ExactArgs(1),
		RunE: func(cmd *coral.Command, args []string) error {
			if err := setLanguage(language); err != nil {
				return err
			}

			if err := restore(maybeFile(mnemonic), args[0]); err != nil {
				return err
			}

			pub := keyPathStyle.Render(args[0])
			priv := keyPathStyle.Render(args[0] + ".pub")
			fmt.Println(baseStyle.Render(fmt.Sprintf("\nSuccessfully restored keys to %s and %s", pub, priv)))
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
	rootCmd.PersistentFlags().StringVarP(&language, "language", "l", "en", "Language")
	rootCmd.AddCommand(restoreCmd, manCmd)

	restoreCmd.PersistentFlags().StringVarP(&mnemonic, "seed", "s", "-", "Seed phrase")
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
	w, _, err := term.GetSize(int(os.Stdout.Fd()))
	if err != nil || w > max {
		return maxWidth
	}
	return w
}

func renderBlock(w io.Writer, s lipgloss.Style, width int, str string) {
	_, _ = io.WriteString(w, s.Copy().Width(width).Render(str))
	_, _ = io.WriteString(w, "\n")
}

func completeColor(truecolor, ansi256, ansi string) string {
	switch lipgloss.ColorProfile() {
	case termenv.TrueColor:
		return truecolor
	case termenv.ANSI256:
		return ansi256
	}
	return ansi
}

// setLanguage sets the language of the big39 mnemonic seed.
func setLanguage(language string) error {
	switch strings.ToLower(language) {
	case "chinese-simplified":
		bip39.SetWordList(wordlists.ChineseSimplified)
	case "chinese-traditional":
		bip39.SetWordList(wordlists.ChineseTraditional)
	case "czech", "cs":
		bip39.SetWordList(wordlists.Czech)
	case "english", "en":
		bip39.SetWordList(wordlists.English)
	case "french", "fr":
		bip39.SetWordList(wordlists.French)
	case "italian", "it":
		bip39.SetWordList(wordlists.Italian)
	case "japanese", "ja":
		bip39.SetWordList(wordlists.Japanese)
	case "korean", "ko":
		bip39.SetWordList(wordlists.Korean)
	case "spanish", "es":
		bip39.SetWordList(wordlists.Spanish)
	default:
		return fmt.Errorf("this language is not supported")
	}
	return nil
}
