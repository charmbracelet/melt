package main

import (
	"crypto/sha256"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/matryer/is"
)

func TestBackupRestoreKnownKey(t *testing.T) {
	const mnemonic = `
		model tone century code pilot
		ball polar sauce machine crisp
		plate soccer salon awake monkey
		own install all broccoli marine
		print smart square impact
	`

	t.Run("backup", func(t *testing.T) {
		is := is.New(t)
		words, err := backup("testdata/test_ed25519")
		is.NoErr(err)
		is.Equal(words, strings.Join(strings.Fields(mnemonic), " "))
	})

	t.Run("restore", func(t *testing.T) {
		is := is.New(t)
		path := filepath.Join(t.TempDir(), "key")
		is.NoErr(restore(path, mnemonic, "ed25519"))

		var digests []string
		for _, f := range []string{path, "testdata/test_ed25519"} {
			digest := sha256.New()
			bts, err := os.ReadFile(f)
			is.NoErr(err)
			_, err = digest.Write(bts)
			is.NoErr(err)
			digests = append(digests, string(digest.Sum(nil)))
		}

		is.Equal(digests[0], digests[1])
	})
}
