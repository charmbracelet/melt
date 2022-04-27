package main

import (
	"fmt"
	"io"
	"os"

	"github.com/charmbracelet/melt/cli"
	"github.com/muesli/coral"
	mcoral "github.com/muesli/mango-coral"
	"github.com/muesli/roff"
)

var (
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
			// nolint: wrapcheck
			return cli.Backup(args[0], language)
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
			// nolint: wrapcheck
			return cli.Restore(args[0], maybeFile(mnemonic), language)
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
				// nolint: wrapcheck
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
