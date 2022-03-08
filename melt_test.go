package melt

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/matryer/is"
)

func TestBackupRestoreKnownKey(t *testing.T) {
	const expectedMnemonic = `
		model tone century code pilot
		ball polar sauce machine crisp
		plate soccer salon awake monkey
		own install all broccoli marine
		print smart square impact
	`
	const expectedSum = "4ec2b1e65bb86ef635991c3e31341c3bdaf6862e9b1efcde0a9c0307081ffc4c"

	t.Run("backup", func(t *testing.T) {
		is := is.New(t)
		mnemonic, sum, err := Backup("testdata/test_ed25519")
		is.NoErr(err)
		is.Equal(mnemonic, strings.Join(strings.Fields(expectedMnemonic), " "))
		is.Equal(sum, expectedSum)
	})

	t.Run("restore", func(t *testing.T) {
		is := is.New(t)
		path := filepath.Join(t.TempDir(), "key")
		sum, err := Restore(path, expectedMnemonic, "ed25519")
		is.NoErr(err)
		is.Equal(sum, expectedSum)
	})
}

func TestRestore(t *testing.T) {
	t.Run("invalid arg", func(t *testing.T) {
		_, err := Restore(t.TempDir(), "does not matter", "rsa")
		is.New(t).True(err != nil)
	})
}
