package cli

import (
	"bytes"
	"crypto/ed25519"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/caarlos0/sshmarshal"
	"github.com/charmbracelet/melt"
	"github.com/mattn/go-tty"
	"github.com/tyler-smith/go-bip39"
	"github.com/tyler-smith/go-bip39/wordlists"
	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
	lang "golang.org/x/text/language"
	"golang.org/x/text/language/display"
)

// Backup a key in the given path using the given language.
func Backup(path, language string) (string, error) {
	if err := setLanguage(language); err != nil {
		return "", err
	}

	return backup(path, nil)
}

// Restore to the given path using the given mnemonic (seed) and language.
func Restore(path, mnemonic, language string) error {
	if err := setLanguage(language); err != nil {
		return err
	}

	if err := restore(mnemonic, path, askNewPassphrase); err != nil {
		return err
	}

	return nil
}

func parsePrivateKey(bts, pass []byte) (interface{}, error) {
	if len(pass) == 0 {
		// nolint: wrapcheck
		return ssh.ParseRawPrivateKey(bts)
	}
	// nolint: wrapcheck
	return ssh.ParseRawPrivateKeyWithPassphrase(bts, pass)
}

func backup(path string, pass []byte) (string, error) {
	bts, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("could not read key: %w", err)
	}

	key, err := parsePrivateKey(bts, pass)
	if err != nil {
		if errors.Is(err, &ssh.PassphraseMissingError{}) {
			pass, err := askKeyPassphrase(path)
			if err != nil {
				return "", err
			}
			return backup(path, pass)
		}
		return "", fmt.Errorf("could not parse key: %w", err)
	}

	switch key := key.(type) {
	case *ed25519.PrivateKey:
		// nolint: wrapcheck
		return melt.ToMnemonic(key)
	default:
		return "", fmt.Errorf("unknown key type: %v", key)
	}
}

func marshallPrivateKey(key ed25519.PrivateKey, pass []byte) (*pem.Block, error) {
	if len(pass) == 0 {
		// nolint: wrapcheck
		return sshmarshal.MarshalPrivateKey(key, "")
	}
	// nolint: wrapcheck
	return sshmarshal.MarshalPrivateKeyWithPassphrase(key, "", pass)
}

func restore(mnemonic, path string, passFn func() ([]byte, error)) error {
	pvtKey, err := melt.FromMnemonic(mnemonic)
	if err != nil {
		// nolint: wrapcheck
		return err
	}

	pass, err := passFn()
	if err != nil {
		return err
	}

	block, err := marshallPrivateKey(pvtKey, pass)
	if err != nil {
		return fmt.Errorf("could not marshal private key: %w", err)
	}

	pubkey, err := ssh.NewPublicKey(pvtKey.Public())
	if err != nil {
		return fmt.Errorf("could not prepare public key: %w", err)
	}

	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil { // nolint: gomnd
		return fmt.Errorf("failed to write private key: %w", err)
	}

	if err := os.WriteFile(path+".pub", ssh.MarshalAuthorizedKey(pubkey), 0o600); err != nil { // nolint: gomnd
		return fmt.Errorf("failed to write public key: %w", err)
	}
	return nil
}

// setLanguage sets the language of the big39 mnemonic seed.
func setLanguage(language string) error {
	list := getWordlist(language)
	if list == nil {
		return fmt.Errorf("this language is not supported")
	}
	bip39.SetWordList(list)
	return nil
}

func sanitizeLang(s string) string {
	return strings.ReplaceAll(strings.ToLower(s), " ", "-")
}

var wordLists = map[lang.Tag][]string{
	lang.Chinese:              wordlists.ChineseSimplified,
	lang.SimplifiedChinese:    wordlists.ChineseSimplified,
	lang.TraditionalChinese:   wordlists.ChineseTraditional,
	lang.Czech:                wordlists.Czech,
	lang.AmericanEnglish:      wordlists.English,
	lang.BritishEnglish:       wordlists.English,
	lang.English:              wordlists.English,
	lang.French:               wordlists.French,
	lang.Italian:              wordlists.Italian,
	lang.Japanese:             wordlists.Japanese,
	lang.Korean:               wordlists.Korean,
	lang.Spanish:              wordlists.Spanish,
	lang.EuropeanSpanish:      wordlists.Spanish,
	lang.LatinAmericanSpanish: wordlists.Spanish,
}

func getWordlist(language string) []string {
	language = sanitizeLang(language)
	tag := lang.Make(language)
	en := display.English.Languages() // default language name matcher
	for t := range wordLists {
		if sanitizeLang(en.Name(t)) == language {
			tag = t
			break
		}
	}
	if tag == lang.Und { // Unknown language
		return nil
	}
	base, _ := tag.Base()
	btag := lang.MustParse(base.String())
	wl := wordLists[tag]
	if wl == nil {
		return wordLists[btag]
	}
	return wl
}

func readPassword(msg string) ([]byte, error) {
	fmt.Fprint(os.Stderr, msg)
	t, err := tty.Open()
	if err != nil {
		return nil, fmt.Errorf("could not open tty: %w", err)
	}
	defer t.Close() // nolint: errcheck
	pass, err := term.ReadPassword(int(t.Input().Fd()))
	if err != nil {
		return nil, fmt.Errorf("could not read passphrase: %w", err)
	}
	return pass, nil
}

func askKeyPassphrase(path string) ([]byte, error) {
	defer fmt.Fprintf(os.Stderr, "\n")
	return readPassword(fmt.Sprintf("Enter the passphrase to unlock %q: ", path))
}

func askNewPassphrase() ([]byte, error) {
	defer fmt.Fprintf(os.Stderr, "\n")
	pass, err := readPassword("Enter passphrase (empty for no passphrase): ")
	if err != nil {
		return nil, err
	}

	confirm, err := readPassword("\nEnter same passphrase again: ")
	if err != nil {
		return nil, fmt.Errorf("could not read password confirmation for key: %w", err)
	}

	if !bytes.Equal(pass, confirm) {
		return nil, fmt.Errorf("Passphareses do not match")
	}

	return pass, nil
}
