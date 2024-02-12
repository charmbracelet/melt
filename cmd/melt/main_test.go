package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/matryer/is"
	"github.com/tyler-smith/go-bip39/wordlists"
	"golang.org/x/crypto/ssh"
)

func TestBackupRestoreKnownKey(t *testing.T) {
	const expectedMnemonic = `
		alter gap broom kitten orient over settle work honey rule
		coach system wage effort mask void solid devote divert
		quarter quote broccoli jaguar lady
	`
	const expectedSum = "ba34175ef608633b29f046b40cce596dd221347b77abba40763eef2e7ae51fe9"
	const expectedFingerprint = "SHA256:tX0ZrsNLIB/ZlRK3vy/HsWIIkyBNhYhCSGmtqtxJcWo"

	t.Run("backup", func(t *testing.T) {
		mnemonic, err := backup("testdata/id_ed25519", nil)
		is := is.New(t)
		is.NoErr(err)
		is.Equal(mnemonic, strings.Join(strings.Fields(expectedMnemonic), " "))
	})

	t.Run("backup file that does not exist", func(t *testing.T) {
		_, err := backup("nope", nil)
		is.New(t).True(err != nil)
	})

	t.Run("backup invalid ssh key", func(t *testing.T) {
		_, err := backup("testdata/not-a-key", nil)
		is.New(t).True(err != nil)
	})

	t.Run("backup key of another type", func(t *testing.T) {
		_, err := backup("testdata/id_rsa", nil)
		is.New(t).True(err != nil)
	})

	t.Run("backup key without password", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skipf("it keeps waiting on a tty for the password")
		}
		_, err := backup("testdata/pwd_id_ed25519", nil)
		is := is.New(t)
		is.True(err != nil)
	})

	t.Run("backup key with password", func(t *testing.T) {
		const expectedMnemonic = `assume knee laundry logic soft fit quantum
			puppy vault snow author alien famous comfort neglect habit
			emerge fabric trophy wine hold inquiry clown govern`

		mnemonic, err := backup("testdata/pwd_id_ed25519", []byte("asd"))
		is := is.New(t)
		is.NoErr(err)
		is.Equal(mnemonic, strings.Join(strings.Fields(expectedMnemonic), " "))
	})

	t.Run("restore", func(t *testing.T) {
		is := is.New(t)
		path := filepath.Join(t.TempDir(), "key")
		is.NoErr(restore(expectedMnemonic, staticPass(nil), restoreToFiles(path)))
		is.Equal(expectedSum, sha256sum(t, path+".pub"))

		bts, err := os.ReadFile(path)
		is.NoErr(err)

		k, err := ssh.ParsePrivateKey(bts)
		is.NoErr(err)

		is.Equal(expectedFingerprint, ssh.FingerprintSHA256(k.PublicKey()))
	})

	t.Run("restore to writer", func(t *testing.T) {
		is := is.New(t)

		var b bytes.Buffer
		is.NoErr(restore(expectedMnemonic, staticPass(nil), restoreToWriter(&b)))

		k, err := ssh.ParsePrivateKey([]byte(b.String()))
		is.NoErr(err)

		is.Equal(expectedFingerprint, ssh.FingerprintSHA256(k.PublicKey()))
	})

	t.Run("restore key with password", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "key")
		is := is.New(t)
		pass := staticPass([]byte("asd"))
		is.NoErr(restore(expectedMnemonic, pass, restoreToFiles(path)))

		bts, err := os.ReadFile(path)
		is.NoErr(err)

		k, err := ssh.ParsePrivateKeyWithPassphrase(bts, []byte("asd"))
		is.NoErr(err)

		is.Equal(expectedFingerprint, ssh.FingerprintSHA256(k.PublicKey()))
	})
}

func TestGetWordlist(t *testing.T) {
	for lang, wordlist := range map[string][]string{
		"cHinese":             wordlists.ChineseSimplified,
		"simplified-cHinese":  wordlists.ChineseSimplified,
		"zH":                  wordlists.ChineseSimplified,
		"zH_haNs":             wordlists.ChineseSimplified,
		"tradITIONAL-cHinese": wordlists.ChineseTraditional,
		"zH_hanT":             wordlists.ChineseTraditional,
		"cZech":               wordlists.Czech,
		"cS":                  wordlists.Czech,
		"eN":                  wordlists.English,
		"eN-gb":               wordlists.English,
		"eNglish":             wordlists.English,
		"american-eNglish":    wordlists.English,
		"british-eNglish":     wordlists.English,
		"fRench":              wordlists.French,
		"fR":                  wordlists.French,
		"iTaliaN":             wordlists.Italian,
		"iT":                  wordlists.Italian,
		"jApanesE":            wordlists.Japanese,
		"jA":                  wordlists.Japanese,
		"kORean":              wordlists.Korean,
		"kO":                  wordlists.Korean,
		"sPanish":             wordlists.Spanish,
		"eS":                  wordlists.Spanish,
		"eS-ER":               wordlists.Spanish,
		"european-spanish":    wordlists.Spanish,
		"ES":                  wordlists.Spanish,
		"zz":                  nil,
		"sOmething":           nil,
	} {
		t.Run(lang, func(t *testing.T) {
			is := is.New(t)
			is.Equal(wordlist, getWordlist(lang))
		})
	}
}

func TestBackupRestoreKnownKeyInJapanse(t *testing.T) {
	const expectedMnemonic = `
	いきおい ざるそば えもの せんめんじょ てあみ ていねい はったつ
    ろこつ すあし のぞく かまう ほくろ らくご けぶかい たおす よゆう
    ひめじし くたびれる ぐんたい なわばり にかい えほん せなか
    そいとげる
	`
	const expectedSum = "ba34175ef608633b29f046b40cce596dd221347b77abba40763eef2e7ae51fe9"
	const expectedFingerprint = "SHA256:tX0ZrsNLIB/ZlRK3vy/HsWIIkyBNhYhCSGmtqtxJcWo"

	// set language to Japanse
	setLanguage("ja")

	// set language back to English
	t.Cleanup(func() {
		setLanguage("en")
	})

	t.Run("backup", func(t *testing.T) {
		mnemonic, err := backup("testdata/id_ed25519", nil)
		is := is.New(t)
		is.NoErr(err)
		is.Equal(mnemonic, strings.Join(strings.Fields(expectedMnemonic), " "))
	})

	t.Run("restore", func(t *testing.T) {
		is := is.New(t)
		path := filepath.Join(t.TempDir(), "key")
		is.NoErr(restore(expectedMnemonic, staticPass(nil), restoreToFiles(path)))
		is.Equal(expectedSum, sha256sum(t, path+".pub"))

		bts, err := os.ReadFile(path)
		is.NoErr(err)

		k, err := ssh.ParsePrivateKey(bts)
		is.NoErr(err)

		is.Equal(expectedFingerprint, ssh.FingerprintSHA256(k.PublicKey()))
	})
}

func TestMaybeFile(t *testing.T) {
	t.Run("is a file", func(t *testing.T) {
		is := is.New(t)
		path := filepath.Join(t.TempDir(), "f")
		content := "test content"
		is.NoErr(os.WriteFile(path, []byte(content), 0o644)) //nolint: gomnd
		is.Equal(content, maybeFile(path))
	})

	t.Run("not a file", func(t *testing.T) {
		is := is.New(t)
		is.Equal("strings", maybeFile("strings"))
	})

	t.Run("stdin", func(t *testing.T) {
		is := is.New(t)
		is.Equal("", maybeFile("-"))
	})
}

func sha256sum(tb testing.TB, path string) string {
	tb.Helper()
	is := is.New(tb)

	bts, err := os.ReadFile(path)
	is.NoErr(err)

	digest := sha256.New()
	_, err = digest.Write(bts)
	is.NoErr(err)

	return hex.EncodeToString(digest.Sum(nil))
}

func staticPass(b []byte) func() ([]byte, error) {
	return func() ([]byte, error) {
		return b, nil
	}
}
