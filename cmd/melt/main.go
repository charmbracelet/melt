package main

import (
	"fmt"
	"io"
	"os"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/melt"
	"github.com/mattn/go-isatty"
	"github.com/muesli/coral"
)

var (
	headerStyle   = lipgloss.NewStyle().Italic(true)
	mnemonicStyle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("63")).Margin(1).Width(60)
	restoreStyle  = lipgloss.NewStyle().Bold(true).Margin(1)

	rootCmd = &coral.Command{
		Use:          "melt",
		Short:        "Backup and restore SSH keys using a mnemonic",
		SilenceUsage: true,
	}
	backupCmd = &coral.Command{
		Use:     "backup",
		Short:   "Backup a SSH private key",
		Example: "melt backup ~/.ssh/id_ed25519",
		Args:    coral.ExactArgs(1),
		RunE: func(cmd *coral.Command, args []string) error {
			mnemonic, sum, err := melt.Backup(args[0])
			if err != nil {
				return err
			}
			if isatty.IsTerminal(os.Stdout.Fd()) {
				fmt.Println(headerStyle.Render(fmt.Sprintf(`
Success!!!

1. Key's sha256 checksum:

%s %s

2. mnemonic set of words

You can now use the words bellow to recreate your key using the 'keys restore' command.
Store them somewhere safe, print or memorize them.
`, sum, args[0])))
				fmt.Println(mnemonicStyle.Render(mnemonic))
			} else {
				fmt.Print(mnemonic)
			}
			return nil
		},
	}

	mnemonic   string
	algo       string
	restoreCmd = &coral.Command{
		Use:     "restore",
		Short:   "Recreate a key using the given mnemonic words",
		Example: "melt restore --mnemonic \"list of words\" ./id_ed25519_restored",
		Args:    coral.ExactArgs(1),
		RunE: func(cmd *coral.Command, args []string) error {
			sum, err := melt.Restore(args[0], maybeFile(mnemonic), algo)
			if err != nil {
				return err
			}

			fmt.Println(restoreStyle.Render(fmt.Sprintf(`Successfully restored keys to '%[1]s' and '%[1]s.pub'.

The private key's sha256sum is:

%s %[1]s
`, args[0], sum)),
			)
			return nil
		},
	}
)

func init() {
	rootCmd.AddCommand(backupCmd, restoreCmd)

	restoreCmd.PersistentFlags().StringVarP(&mnemonic, "mnemonic", "m", "-", "Mnemonic set of words given by the backup command")
	restoreCmd.PersistentFlags().StringVar(&algo, "algo", "ed25519", "Key algorithm")
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
