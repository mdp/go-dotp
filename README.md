# Go dOTP

Libary and CLI for working with dOTP

## Install from compiled binary

Find the binaries at [github.com/mdp/go-dotp/releases](https://github.com/mdp/go-dotp/releases)

## Install from source

#### Just the ibrary

`go get github.com/mdp/go-dotp`

#### The library and CLI

`go get github.com/mdp/go-dotp/...`

## Usage

#### Two Factor SSH

Inside of sshd_config (usually at /etc/ssh/sshd_config)

```
Match Group twofactorusers
  ForceCommand /location/of/bin/dotp sshauth
```

Users in the 'twofactorusers' group will now need to have their dOTP PublicID stored
inside of $HOME/.dotp_id

When they login to SSH they will be presented with a QRCode Challage which must be scanned with
a dOTP mobile application to decrypt the One Time Password

#### Generate a challenged for a given Public ID

`dotp challenge --pubid "E7jY95KejKzcXmhZct2Kvcz2QSap4vVTb89S6eKkBXuhK" myotp123`

#### Generate a KeyPair from a seed

Seed should always come from a random source.

```
dotp generate `cat /dev/random | env LC_CTYPE=C tr -dc 'a-zA-Z0-9' | fold -w 64 | head -n 1`
```


