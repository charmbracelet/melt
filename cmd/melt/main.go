package main

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/melt/cli"
	"github.com/mattn/go-isatty"
	"github.com/muesli/coral"
	mcoral "github.com/muesli/mango-coral"
	"github.com/muesli/reflow/wordwrap"
	"github.com/muesli/roff"
	"github.com/muesli/termenv"
	"golang.org/x/term"
)

const (
	maxWidth = 72
)

var (
	baseStyle = lipgloss.NewStyle().Margin(0, 0, 1, 2) // nolint: gomnd
	violet    = lipgloss.Color(completeColor("#6B50FF", "63", "12"))
	cmdStyle  = lipgloss.NewStyle().
			Foreground(lipgloss.AdaptiveColor{Light: "#FF5E8E", Dark: "#FF5E8E"}).
			Background(lipgloss.AdaptiveColor{Light: completeColor("#ECECEC", "255", "7"), Dark: "#1F1F1F"}).
			Padding(0, 1)
	mnemonicStyle = baseStyle.Copy().
			Foreground(violet).
			Background(lipgloss.AdaptiveColor{Light: completeColor("#EEEBFF", "255", "7"), Dark: completeColor("#1B1731", "235", "8")}).
			Padding(1, 2) // nolint: gomnd
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
			path := args[0]
			mnemonic, err := cli.Backup(path, language)
			if err != nil {
				// nolint: wrapcheck
				return err
			}
			if isatty.IsTerminal(os.Stdout.Fd()) {
				b := strings.Builder{}
				w := getWidth(maxWidth)

				b.WriteRune('\n')
				meltCmd := cmdStyle.Render(path)
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
					path+` restore`+lang+` ./my-key --seed "`+mnemonic+`"`,
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
			path := args[0]
			if err := cli.Restore(path, maybeFile(mnemonic), language); err != nil {
				// nolint: wrapcheck
				return err
			}
			pub := keyPathStyle.Render(path)
			priv := keyPathStyle.Render(path + ".pub")
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
	// nolint: exhaustive
	switch lipgloss.ColorProfile() {
	case termenv.TrueColor:
		return truecolor
	case termenv.ANSI256:
		return ansi256
	}
	return ansi
}
