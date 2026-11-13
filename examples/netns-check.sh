#!/bin/sh
# Refresh a keyring inside a network namespace with no route to the internet.
# The only way out is a Unix socket to the Nym SOCKS5 client on the host, so
# every key that arrives came through the mixnet; a clearnet fallback, a
# local DNS lookup or a gpg/dirmngr side channel would simply fail.
#
# The keyring is copied first; the one you pass is not changed.
#
# Usage: examples/netns-check.sh GNUPGHOME [path/to/nymkeys]
# Needs: unprivileged user namespaces (unshare -rn), iproute2, python3, curl,
# gpg, and `nymkeys nym start` already running on the host.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
src=$1
NYMKEYS=$(realpath "${2:-$(command -v nymkeys)}")
PROXY=${NYMKEYS_PROXY:-127.0.0.1:1095}
dir=$(mktemp -d)
mkdir -m 700 "$dir/gnupg"
gpg --homedir "$src" --batch --no-autostart --export | gpg --homedir "$dir/gnupg" --batch --no-autostart --quiet --import
python3 "$here/unix-relay.py" listen-unix "$dir/nym.sock" "$PROXY" &
relay=$!
trap 'kill $relay 2>/dev/null || true; rm -rf "$dir"' EXIT INT TERM
sleep 0.5

unshare -rn sh -eu -c '
dir=$1 here=$2 nymkeys=$3
ip link set lo up
python3 "$here/unix-relay.py" listen-tcp 127.0.0.1:1095 "$dir/nym.sock" >/dev/null 2>&1 &
relay=$!
trap "kill \$relay 2>/dev/null || true" EXIT
for i in $(seq 20); do python3 -c "import socket; socket.create_connection((\"127.0.0.1\", 1095)).close()" 2>/dev/null && break; sleep 0.2; done

echo "== this namespace has no route out:"
ip -br addr
curl -sS --max-time 5 -o /dev/null https://1.1.1.1/ 2>&1 | sed "s/^/   /" || true
getent hosts keys.openpgp.org >/dev/null 2>&1 && echo "   local DNS works (unexpected)" || echo "   local DNS: no answer"
echo
echo "== nymkeys list"
"$nymkeys" list --homedir "$dir/gnupg" 2>&1 | sed "s/^/   /"
echo
echo "== nymkeys refresh --proxy 127.0.0.1:1095 --now  (the keyring is out of date)"
"$nymkeys" refresh --homedir "$dir/gnupg" --proxy 127.0.0.1:1095 --now 2>&1 | sed "s/^/   /"
echo
echo "== the same again (nothing new now)"
"$nymkeys" refresh --homedir "$dir/gnupg" --proxy 127.0.0.1:1095 --now 2>&1 | sed "s/^/   /"
echo
echo "== with the proxy gone: no fallback, it just fails"
"$nymkeys" refresh --homedir "$dir/gnupg" --proxy 127.0.0.1:1 --now 2>&1 | sed "s/^/   /" || echo "   (exit $?)"
' sh "$dir" "$here" "$NYMKEYS"
