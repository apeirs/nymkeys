#!/bin/sh
# Make an out-of-date copy of a keyring, to see a refresh do something: every
# subkey and signature made after CUTOFF is dropped, as if the keyring had not
# been refreshed since then. Public keys only; the source keyring is not touched.
#
# Usage: examples/make-stale.sh SRC_GNUPGHOME DST_GNUPGHOME [CUTOFF=2024-01-01]
set -eu
src=$1 dst=$2 cutoff=${3:-2024-01-01}
mkdir -p "$dst" && chmod 700 "$dst"
gpg --homedir "$src" --batch --no-autostart --export \
    --export-filter "drop-subkey=key_created_d > $cutoff" |
  gpg --homedir "$dst" --batch --no-autostart --quiet --import \
    --import-filter "drop-sig=sig_created_d > $cutoff"
gpg --homedir "$dst" --batch --with-colons --list-keys | awk -F: '
  $1=="pub" {n++} $1=="sub" {s++} END {printf "%d keys, %d subkeys\n", n, s}'
