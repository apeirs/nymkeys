# nymkeys

Refresh your OpenPGP keyring through the [Nym mixnet](https://nym.com), one key at a time, at random
times, each key through a new throwaway mixnet identity.

```
$ nymkeys refresh --over 3m
refreshing 3 key(s) in random order over ~3m0s from vks,wkd; a new Nym client and a random exit gateway for every key
2026-11-13 08:24:10  [1/3] next in 38s
2026-11-13 08:25:00  4E2C6E8793298290  Tor Browser Developers (signing…  updated    +1 subkey, +1 sig  [vks 39 KB, wkd 7 KB; 11.9s]
                      via new Nym client, exit node 2950 (CA), ready in 3.1s
2026-11-13 08:25:00  [2/3] next in 4s
2026-11-13 08:25:42  DBB802B258ACD84F  Tails developers <tails@tails.n…  updated    +1 subkey, +1 sig  [vks 42 KB, wkd none; 37.6s]
                      via new Nym client, exit node 2871 (GR), ready in 4.5s
2026-11-13 08:25:42  [3/3] next in 5s
2026-11-13 08:25:53  528897B826403ADA  Werner Koch (dist signing 2020)   unchanged  [vks 213 B, wkd -; 6.4s]
                      via new Nym client, exit node 2718 (BR), ready in 1.9s
done: 2 updated, 1 unchanged
```

(A real run on the Nym mainnet, 13 Nov 2026, on an out-of-date copy of a keyring: the Tails and Tor
Browser signing keys got their current signing subkeys. Three keys, three new mixnet identities, three
exit gateways in three countries.)

## Why

`gpg --refresh-keys` asks a keyserver for every key you hold, in one burst, from your IP address. The
list of keys you refresh is your social graph: who you write to, which projects' releases you verify,
which journalists or lawyers you talk to. Whoever runs the keyserver, or watches the line, gets that
list with a timestamp and your address on it.

The fix has existed for Tor users for years: [parcimonie](https://salsa.debian.org/intrigeri/parcimonie)
refreshes one key at a time, at random times, each over a separate Tor circuit. There was nothing like
it for Nym. nymkeys is that idea built on the mixnet, which adds what Tor cannot: cover traffic and
per-packet mixing delays, so even an observer who sees both your link and the keyserver's has a hard
time matching a request to you by timing.

It also does the things `gpg --refresh-keys` does badly:

- **It only takes what it asked for.** An answer must contain exactly the requested key and nothing
  else (no secret keys, no extra keys), must be under 1 MiB (flooded keys are dropped), and is merged
  with `merge-only,self-sigs-only`: new subkeys, new expiry dates, new user IDs and revocations come
  in; third-party certifications (the spam that broke the SKS network) and new keys never do.
- **It says what changed**: `NOW REVOKED`, `expires 2030-11-18`, `+1 subkey, +1 sig`. A revocation
  is the one update you cannot afford to miss.
- **It asks the sources people actually use now**: keys.openpgp.org (VKS) and the key's own domain
  (WKD, which the Tor Project, kernel.org, Proton and others publish), plus HKP if you want it.

## How it uses the mixnet

```
           ┌──────────── per key, a new one ────────────┐
 nymkeys ─▶│ nym-socks5-client (new keys, temp $HOME)    │─▶ entry gateway ─▶ 3 mix layers ─▶ exit gateway
           └─────────────────────────────────────────────┘        Sphinx packets, cover traffic   │ network requester
                                                                                                     ▼
                                                                         keys.openpgp.org / openpgpkey.<domain>
```

For every key, nymkeys:

1. picks a random exit gateway with a network requester from the Nym API (performance ≥ 0.95 by
   default);
2. creates a **new** `nym-socks5-client` in a private 0700 temporary directory (a fresh mixnet
   identity, the client picks its own entry gateway), with reply SURBs on, so the exit never learns
   the client's address;
3. sends HTTPS requests for that one key through it: SOCKS5 with the hostname (ATYP 3), so DNS is
   resolved at the exit, never on your machine; TLS end to end to the keyserver; no User-Agent,
   no cookies, `https://` only, also on redirects;
4. checks the answer with `gpg --import-options show-only`, merges it, and then stops the client and
   deletes its identity.

Between keys it sleeps a random, exponentially distributed time (a Poisson process), and the order of
the keys is shuffled. `nymkeys daemon` runs forever and refreshes a random key after each random gap,
so each key comes up about once per `--period` (default one week), the same schedule shape as
parcimonie. Revoked keys are skipped (a revocation is final) unless you pass
`--include-revoked`. The daemon waits before the first refresh too, so a reboot does not cause a burst.

If the Nym client cannot start, or `--proxy` points nowhere, nothing is sent. There is no code path
that dials a keyserver directly; the test suite checks that (and a [mutation run](examples/mutations.txt)
checks that the tests notice when a guard is removed).

## Install

You need Go 1.26+, GnuPG 2.2+ and Nym's `nym-socks5-client` release binary
([nymtech/nym releases](https://github.com/nymtech/nym/releases), the `nym-socks5-client` asset for your
platform).

```sh
go install github.com/apeirs/nymkeys/cmd/nymkeys@latest
install -m 755 nym-socks5-client ~/.local/bin/          # or anywhere on $PATH
export NYMKEYS_NYM_SOCKS5=~/.local/bin/nym-socks5-client  # if it is not on $PATH
```

## Usage

```sh
nymkeys list                      # your keys, their state, which WKD domains would be asked
nymkeys refresh                   # every key once, spread over about an hour
nymkeys refresh --over 8h         # the same, slower
nymkeys refresh FPR [FPR...]      # only these keys
nymkeys refresh --dry-run         # fetch and check, change nothing
nymkeys daemon                    # forever; each key about once a week at random times
nymkeys fetch FPR                 # add a new key by its full fingerprint (checked before import)
nymkeys fetch --email a@b.org FPR # ... also asking b.org's WKD
nymkeys wkd-url someone@example.org   # print the WKD URLs (offline)
```

Useful flags: `--homedir` (a GnuPG home other than the default), `--sources vks,wkd,hkp`,
`--keyserver URL` / `--hkp URL` (https only), `--json` (one object per key), `-v` (each mixnet step),
`--include-revoked`, `--timeout 3m` (per key and attempt, client start included), `--retries 1` (when
no source answered at all, try the key again through a new Nym client: a mixnet route can stall).

`nymkeys fetch` takes only a full 40- or 64-hex-digit fingerprint. Short and long key IDs can be forged
cheaply, so they are refused.

### Run it as a user service

```sh
cp contrib/nymkeys.service ~/.config/systemd/user/   # edit the two paths in it if needed
systemctl --user daemon-reload
systemctl --user enable --now nymkeys
journalctl --user -u nymkeys -f
```

### Faster: one long-lived client

```sh
nymkeys nym setup     # init a client on 127.0.0.1:1095 with a random exit (reply SURBs on)
nymkeys nym start
nymkeys refresh --proxy 127.0.0.1:1095 --now
```

This skips the 1-4 s client start per key, but every key then goes through the same Nym client and the
same exit, which can link the requests. Use it for a one-off check, not as the default.

## Threat model

**Protects against:**

- the keyserver (or the domain's WKD server) learning your IP address or linking your keys to each
  other: each request comes from a different, new mixnet identity through a randomly chosen exit, at a
  random time, and the keys are asked for in random order;
- your ISP or local network learning which keys you hold or which domains you look up: all they see is
  Sphinx packets to a Nym entry gateway, including cover traffic; there is no local DNS lookup;
- an exit gateway linking your keys: each exit sees at most one key (with per-key clients) and never
  your address (reply SURBs);
- a keyserver feeding you junk: wrong keys, extra keys, secret keys, oversized "flooded" keys and
  third-party certification spam are rejected or dropped; HTTPS is required and certificates are
  checked against the system roots.

**Does not protect against:**

- a keyserver withholding an update (a "freeze" attack). Asking two sources (VKS and WKD) helps; if
  you depend on a revocation, ask the key owner how they publish it;
- the exit gateway, and the keyserver, seeing *which* key is asked for. They just cannot tell by whom.
  With WKD, the exit also sees the domain;
- an adversary who can watch your link and the keyserver's for a long time and correlate volume. The
  mixnet makes this much harder than over Tor, not impossible;
- the Nym API query that lists exit gateways. It goes out directly (it is public information and
  the same for every user), so the API host learns that this machine uses Nym, as the Nym client's own
  start-up does;
- a compromised machine, gpg, or `nym-socks5-client`.

## Limits

- **keys.openpgp.org strips user IDs** whose owners never confirmed their address. Such an answer
  still brings new subkeys and revocations, but `nymkeys fetch` cannot import a new key from it (gpg
  needs a user ID); use `--sources hkp` (keyserver.ubuntu.com) or `--email` for WKD.
- **Speed.** Starting a client takes 1-4 s and a key 5-15 s through the mixnet. A WKD domain without an
  `openpgpkey.` host costs up to 20 s per refresh: through the mixnet a name that does not resolve
  looks like a connection that never answers, so nymkeys waits `20s` before trying the direct method.
- **Linux only** for now (process groups and `Pdeathsig` keep the per-key clients from outliving
  nymkeys). macOS would need a small port.
- **Disk:** each per-key client writes a few MB to a temporary directory and deletes it afterwards.
- It refreshes public keys only. It never reads, exports or touches secret keys, and it never talks to
  gpg-agent or dirmngr (`--no-autostart`); turn off `auto-key-retrieve` in gpg.conf yourself if you want
  gpg itself to stay off the network.
- Nym's network requesters can refuse hosts that are not on their allow list. All exits tested so far
  allowed keys.openpgp.org, keyserver.ubuntu.com and the WKD hosts above.

## Proof it works

Everything below ran against the live Nym mainnet on 13 Nov 2026, with the release
`nym-socks5-client` (build 2026-10-01).

- [`examples/live-fetch.txt`](examples/live-fetch.txt): fetching the Tails, Tor Browser and GnuPG
  release signing keys into an empty keyring, each through a new client and a different exit.
- [`examples/live-refresh.txt`](examples/live-refresh.txt): refreshing an out-of-date copy of that
  keyring (made with [`examples/make-stale.sh`](examples/make-stale.sh), which drops subkeys and
  signatures newer than a date): 2 keys updated with their current signing subkeys.
- [`examples/live-daemon.txt`](examples/live-daemon.txt): `nymkeys daemon --period 3m` for six
  minutes, stopped with SIGTERM: random gaps before every key, a new client per key, nothing left
  running or on disk afterwards.
- [`examples/live-netns.txt`](examples/live-netns.txt): the same inside a network namespace with no
  route out (`examples/netns-check.sh`): `curl` and DNS fail, the refresh succeeds, because the only way
  out is the Nym client's socket. With the proxy gone it fails, and nothing falls back.

## Tests

```sh
go test -race ./...            # needs gpg; makes throwaway keys in a temp dir
python3 examples/mutate.py .   # breaks each guard in turn and checks a test fails
```

The tests run real gpg on throwaway keys (an old and a new version, a revoked key, a key certified by a
stranger, a secret key) behind a fake HTTPS keyserver and a fake SOCKS5 proxy that records what was
asked for. They check: only hostnames go to the proxy (no local DNS), no User-Agent, no fallback when the
proxy is down, plain-HTTP keyservers and redirects refused, wrong/extra/secret/oversized answers
rejected, certification spam dropped, revocations reported, random order, exponential gaps, the daemon
sleeping before each refresh, a stalled route retried through a new session, a dead WKD host costing
seconds rather than minutes, and each per-key client living in its own directory with a clean
environment and getting deleted. [`examples/mutations.txt`](examples/mutations.txt): 22 of 22 guards
removed, 22 caught.

## License

MIT, see [LICENSE](LICENSE).
