package main

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/matryer/is"
)

func TestBackupRestoreKnownKey(t *testing.T) {
	const expectedMnemonic = `
		alter gap broom kitten orient over settle work honey rule
		coach system wage effort mask void solid devote divert
		quarter quote broccoli jaguar lady
	`
	const expectedSum = "ba34175ef608633b29f046b40cce596dd221347b77abba40763eef2e7ae51fe9"

	t.Run("backup", func(t *testing.T) {
		is := is.New(t)
		mnemonic, err := backup("testdata/id_ed25519")
		is.NoErr(err)
		is.Equal(mnemonic, strings.Join(strings.Fields(expectedMnemonic), " "))
	})

	t.Run("restore", func(t *testing.T) {
		is := is.New(t)
		path := filepath.Join(t.TempDir(), "key")
		is.NoErr(restore(expectedMnemonic, path))
		is.Equal(expectedSum, sha256sum(t, path+".pub"))
	})
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

func sha256sum(tb testing.TB, path string) string {
	tb.Helper()
	is := is.New(tb)
	bts, err := os.ReadFile(path)
	is.NoErr(err)
	tb.Log(string(bts))
	digest := sha256.New()
	_, err = digest.Write(bts)
	is.NoErr(err)
	return hex.EncodeToString(digest.Sum(nil))
}
