package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
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
		mnemonic, err := backup("testdata/test_ed25519")
		is.NoErr(err)
		is.Equal(mnemonic, strings.Join(strings.Fields(expectedMnemonic), " "))
	})

	t.Run("restore", func(t *testing.T) {
		is := is.New(t)
		path := filepath.Join(t.TempDir(), "key")
		is.NoErr(restore(path, expectedMnemonic))
	})
}

func sha256sum(bts []byte) (string, error) {
	digest := sha256.New()
	if _, err := digest.Write(bts); err != nil {
		return "", fmt.Errorf("failed to sha256sum key: %w", err)
	}
	return hex.EncodeToString(digest.Sum(nil)), nil
}

func TestMaybeFile(t *testing.T) {
	t.Run("is a file", func(t *testing.T) {
		is := is.New(t)
		path := filepath.Join(t.TempDir(), "f")
		content := "test content"
		is.NoErr(os.WriteFile(path, []byte(content), 0o644))
		is.Equal(content, maybeFile(path))
	})

	t.Run("not a file", func(t *testing.T) {
		is := is.New(t)
		is.Equal("strings", maybeFile("strings"))
	})
}
