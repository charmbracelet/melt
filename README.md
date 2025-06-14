# Melt

<p>
    <img src="https://stuff.charm.sh/melt/melt-header.png" width="294" alt="Melt Mascot"><br>
        <a href="https://github.com/charmbracelet/melt/releases"><img src="https://img.shields.io/github/release/charmbracelet/melt.svg" alt="Latest Release"></a>
    <a href="https://github.com/charmbracelet/melt/actions"><img src="https://github.com/charmbracelet/melt/workflows/build/badge.svg" alt="Build Status"></a>
</p>

Backup and restore SSH private keys using memorizable seed phrases.

<img width="600" alt="Melt example" src="https://stuff.charm.sh/melt/melt-example.png">

## Installation

### Package Manager

```bash
# macOS or Linux
brew install charmbracelet/tap/melt

# Arch Linux (btw)
yay -S melt-bin

# Windows (with Scoop)
scoop bucket add https://github.com/charmbracelet/scoop-bucket.git
scoop install melt

# Nix
nix-env -iA nixpkgs.melt

# Debian/Ubuntu
sudo mkdir -p /etc/apt/keyrings
curl -fsSL https://repo.charm.sh/apt/gpg.key | sudo gpg --dearmor -o /etc/apt/keyrings/charm.gpg
echo "deb [signed-by=/etc/apt/keyrings/charm.gpg] https://repo.charm.sh/apt/ * *" | sudo tee /etc/apt/sources.list.d/charm.list
sudo apt update && sudo apt install melt

# Fedora/RHEL
echo '[charm]
name=Charm
baseurl=https://repo.charm.sh/yum/
enabled=1
gpgcheck=1
gpgkey=https://repo.charm.sh/yum/gpg.key' | sudo tee /etc/yum.repos.d/charm.repo
sudo yum install melt
```

You can download a binary or package from the [releases][releases] page.

### Go

Or just install it with `go`:
```bash
go install github.com/charmbracelet/melt/cmd/melt@latest
```

## Build (requires Go 1.17+)

```bash
git clone https://github.com/charmbracelet/melt.git
cd melt
go build ./cmd/melt/
```

[releases]: https://github.com/charmbracelet/melt/releases

## Usage

The CLI usage looks like the following:

```shell
# Generate a seed phrase from an SSH key
melt ~/.ssh/id_ed25519

# Generate a seed phrase from a SSH key from standard input
cat ~/.ssh/id_ed25519 | melt

# Rebuild the key from the seed phrase
melt restore ./my-key --seed "seed phrase"

# Rebuild the key and print it to standard output
cat words | melt restore -
```

You can also pipe to and from a file:

```shell
melt ~/.ssh/id_ed25519 > words
melt restore ./recovered_id_ed25519 < words
```

## How it Works

It all comes down to the private key __seed__:

> Ed25519 keys start life as a 32-byte (256-bit) uniformly random binary seed (e.g. the output of SHA256 on some random input). The seed is then hashed using SHA512, which gets you 64 bytes (512 bits), which is then split into a “left half” (the first 32 bytes) and a “right half”. The left half is massaged into a curve25519 private scalar “a” by setting and clearing a few high/low-order bits. The pubkey is generated by multiplying this secret scalar by “B” (the generator), which yields a 32-byte/256-bit group element “A”.[^1]

Knowing that, we open the key and extract its seed, and use it as __entropy__ for the [bip39][] algorithm, which states:

> The mnemonic must encode entropy in a multiple of 32 bits. With more entropy security is improved but the sentence length increases. We refer to the initial entropy length as ENT. The allowed size of ENT is 128-256 bits.[^2]

Doing that, we get the __mnemonic__ set of words back.

To restore, we:

- get the __entropy__ from the __mnemonic__
- the __entropy__ is effectively the key __seed__, so we use it to create a SSH key pair
- the key is effectively the same that was backed up, as the key is the same.
You can verify the keys by checking the public key fingerprint, which should be
the same in the original and _restored_ key.

[^1]: Warner, Brian. [How do Ed5519 keys work?](https://blog.mozilla.org/warner/2011/11/29/ed25519-keys/) (2011)
[^2]: Palatinus, Marek et al. [Mnemonic code for generating deterministic keys](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki) (2013)

[bip39]: https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki

## Caveats

- At this time, only `ed25519` keys are supported.
- If your public key has a memo (usually the user@host in which it was
generated), it'll be lost.
That info (or any other) can be added to the public key manually later,
as it's effectively not used for signing/verifying.
- Some bytes of your private key might change, due to their random block.
The key is effectively the same though.

### Restoring the memo

We can use `ssh-keygen` to add a memo to our restored keys.

If you ran the following command to restore a key:

```shell
melt restore ./my-key --seed "witness shoe deputy celery debate myth \
  title sign dish bone powder velvet reveal midnight blast mobile \
  valid cycle announce valid item interest cinnamon cake"
Restoring key to ./my-key and ./my-key.pub...
Enter new passphrase (empty for no passphrase):
Enter same passphrase again:

  Successfully restored keys to ./my-key and ./my-key.pub
```

You can verify that the memo is not there:

```shell
cat my-key.pub
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKThPEoe20Wi5zAfyI+gTrTMnODbRtYtQRUZYIvfV19C
```

Run this command on the restored key:

```shell
ssh-keygen -c -C melted-again@charm.sh -f ./my-key
Old comment:
Comment 'melted-again@charm.sh' applied
```

And check to see your memo is set:

```shell
cat my-key.pub
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKThPEoe20Wi5zAfyI+gTrTMnODbRtYtQRUZYIvfV19C melted-again@charm.sh
```

## Contributing

See [contributing][contribute].

[contribute]: https://github.com/charmbracelet/melt/contribute

## Feedback

We’d love to hear your thoughts on this project. Feel free to drop us a note!

* [Twitter](https://twitter.com/charmcli)
* [The Fediverse](https://mastodon.social/@charmcli)
* [Discord](https://charm.sh/chat)

## License

[MIT](https://github.com/charmbracelet/melt/raw/main/LICENSE)

***

Part of [Charm](https://charm.sh).

<a href="https://charm.sh/"><img alt="The Charm logo" src="https://stuff.charm.sh/charm-badge.jpg" width="400"></a>

Charm热爱开源 • Charm loves open source
