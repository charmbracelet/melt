package melt

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"github.com/matryer/is"
)

func TestToMnemonic(t *testing.T) {
	t.Run("invalid", func(t *testing.T) {
		is := is.New(t)
		w, err := toMnemonic([]byte{})
		is.Equal(w, "")
		is.True(err != nil)
	})

	t.Run("valid", func(t *testing.T) {
		is := is.New(t)
		_, k, err := ed25519.GenerateKey(rand.Reader)
		is.NoErr(err)
		w, err := ToMnemonic(&k)
		is.NoErr(err)
		is.True(w != "")
	})
}

func TestFromMnemonic(t *testing.T) {
	t.Run("invalid", func(t *testing.T) {
		is := is.New(t)
		key, err := FromMnemonic("nope nope nope")
		is.Equal(key, nil)
		is.True(err != nil)
	})

	t.Run("valid", func(t *testing.T) {
		is := is.New(t)
		key, err := FromMnemonic(`
			alter gap broom kitten orient over settle work honey rule
			coach system wage effort mask void solid devote divert
			quarter quote broccoli jaguar lady
		`)
		is.NoErr(err)
		is.True(key != nil)
	})
}
