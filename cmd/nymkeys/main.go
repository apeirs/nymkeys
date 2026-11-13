// Command nymkeys: refresh your OpenPGP keyring through the Nym mixnet, one
// key at a time, at random times, each key through a new Nym client and exit.
//
//	nymkeys list              keys in the keyring and where each would be asked
//	nymkeys refresh           refresh every key, spread over --over (default 1h)
//	nymkeys daemon            refresh forever, each key about once per --period
//	nymkeys fetch FPR         add a new key by its full fingerprint
//	nymkeys nym setup|...     run a long-lived nym-socks5-client (for --proxy)
package main

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"math/rand/v2"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/apeirs/nymkeys/keyring"
	"github.com/apeirs/nymkeys/mixnet"
	"github.com/apeirs/nymkeys/nym"
	"github.com/apeirs/nymkeys/refresh"
	"github.com/apeirs/nymkeys/source"
	"github.com/apeirs/nymkeys/wkd"
)

const version = "0.1.0"

func die(err error) {
	fmt.Fprintln(os.Stderr, "nymkeys:", err)
	os.Exit(1)
}

// multi is a repeatable, comma-splitting string flag.
type multi []string

func (m *multi) String() string { return strings.Join(*m, ",") }
func (m *multi) Set(s string) error {
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			*m = append(*m, p)
		}
	}
	return nil
}

// parse allows flags after positional arguments.
func parse(fs *flag.FlagSet, args []string) []string {
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			os.Exit(2)
		}
		args = fs.Args()
		if len(args) == 0 {
			return pos
		}
		pos = append(pos, args[0])
		args = args[1:]
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `nymkeys %s: refresh your OpenPGP keyring through the Nym mixnet

  nymkeys list    [flags]          keys in the keyring, and where each would be asked
  nymkeys refresh [flags] [FPR...] refresh keys one at a time in random order, spread over --over
  nymkeys daemon  [flags]          refresh forever; each key about once per --period, at random times
  nymkeys fetch   [flags] FPR      add a new key by its full fingerprint (checked before import)
  nymkeys wkd-url ADDRESS          print the WKD URLs for an address (offline)
  nymkeys nym setup|start|stop|status|exits   a long-lived nym-socks5-client for --proxy (port %d)
  nymkeys version

By default every key goes through a NEW, throwaway nym-socks5-client (new mixnet identity, random
exit gateway) that is deleted afterwards. Point --binary or $NYMKEYS_NYM_SOCKS5 at Nym's release
binary. --proxy uses one running client instead (faster; the exit can then link your requests).
Nothing ever goes out without the mixnet. 'nymkeys refresh -h' for the flags.
`, version, nym.DefaultPort)
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	args := os.Args[2:]
	switch os.Args[1] {
	case "list":
		cmdList(args)
	case "refresh":
		cmdRefresh(args, false)
	case "daemon":
		cmdRefresh(args, true)
	case "fetch":
		cmdFetch(args)
	case "wkd-url":
		cmdWKD(args)
	case "nym":
		cmdNym(args)
	case "version", "--version", "-V":
		fmt.Println("nymkeys", version)
	case "help", "-h", "--help":
		usage()
	default:
		usage()
		os.Exit(2)
	}
}

// ---------------------------------------------------------------- common flags

type common struct {
	fs        *flag.FlagSet
	homedir   *string
	gpgBin    *string
	proxy     *string
	binary    *string
	sources   *string
	keyserver *string
	hkp       *string
	caFile    *string
	maxBytes  *int64
	timeout   *time.Duration
	retries   *int
	minPerf   *float64
	jsonOut   *bool
	verbose   *bool
	dryRun    *bool
}

func newCommon(name, defSources string) *common {
	fs := flag.NewFlagSet(name, flag.ExitOnError)
	return &common{
		fs:        fs,
		homedir:   fs.String("homedir", os.Getenv("GNUPGHOME"), "GnuPG home directory (default: gpg's, $GNUPGHOME)"),
		gpgBin:    fs.String("gpg", "gpg", "gpg binary"),
		proxy:     fs.String("proxy", os.Getenv("NYMKEYS_PROXY"), "use this running nym-socks5-client (host:port) for every key instead of a new client per key ($NYMKEYS_PROXY)"),
		binary:    fs.String("binary", "", "nym-socks5-client release binary for per-key clients ($NYMKEYS_NYM_SOCKS5, $PATH)"),
		sources:   fs.String("sources", defSources, "where to ask, in order: vks (keys.openpgp.org), wkd (the key's email domains), hkp (keyserver.ubuntu.com)"),
		keyserver: fs.String("keyserver", "https://keys.openpgp.org", "VKS keyserver (https only)"),
		hkp:       fs.String("hkp", "https://keyserver.ubuntu.com", "HKP keyserver for the hkp source (https only)"),
		caFile:    fs.String("ca", "", "extra PEM CA bundle (a private keyserver with its own CA)"),
		maxBytes:  fs.Int64("max-bytes", source.DefaultMaxBytes, "drop answers larger than this (flooded keys)"),
		timeout:   fs.Duration("timeout", 3*time.Minute, "per key and attempt, mixnet client start included"),
		retries:   fs.Int("retries", 1, "when no source answers, try the key again this many times, each through a new Nym client"),
		minPerf:   fs.Float64("min-performance", 0.95, "minimum exit gateway performance (per-key clients)"),
		jsonOut:   fs.Bool("json", false, "JSON output, one object per key"),
		verbose:   fs.Bool("v", false, "show each mixnet step"),
		dryRun:    fs.Bool("dry-run", false, "fetch and check, import nothing"),
	}
}

func (c *common) gpg() keyring.GPG { return keyring.GPG{Bin: *c.gpgBin, Home: *c.homedir} }

func (c *common) roots() *x509.CertPool {
	if *c.caFile == "" {
		return nil
	}
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	b, err := os.ReadFile(*c.caFile)
	if err != nil {
		die(err)
	}
	if !pool.AppendCertsFromPEM(b) {
		die(fmt.Errorf("%s: no PEM certificates", *c.caFile))
	}
	return pool
}

func (c *common) tracer() mixnet.Tracer {
	if !*c.verbose {
		return nil
	}
	return func(format string, args ...any) {
		fmt.Fprintf(os.Stderr, "    · "+format+"\n", args...)
	}
}

// ---------------------------------------------------------------- sessions

type sharedSession struct {
	client *http.Client
	desc   string
}

func (s *sharedSession) Client() *http.Client { return s.client }
func (s *sharedSession) Describe() string     { return s.desc }
func (s *sharedSession) Close()               { s.client.CloseIdleConnections() }

type ephSession struct {
	e      *nym.Ephemeral
	client *http.Client
}

func (s *ephSession) Client() *http.Client { return s.client }
func (s *ephSession) Describe() string {
	p := s.e.Provider
	return fmt.Sprintf("new Nym client, exit %s, ready in %.1fs", exitName(p), s.e.Startup.Seconds())
}
func (s *ephSession) Close() {
	s.client.CloseIdleConnections()
	s.e.Close()
}

// exitCache keeps the exit gateway list for a few hours (the nym-api is asked
// directly, like nym-socks5-client itself does for its topology).
type exitCache struct {
	mu      sync.Mutex
	minPerf float64
	list    []nym.ExitProvider
	at      time.Time
}

func (x *exitCache) get() ([]nym.ExitProvider, error) {
	x.mu.Lock()
	defer x.mu.Unlock()
	if x.list != nil && time.Since(x.at) < 6*time.Hour {
		return x.list, nil
	}
	ps, err := nym.ListExitProviders(nym.NymAPI, x.minPerf)
	if err != nil {
		if x.list != nil {
			return x.list, nil
		}
		return nil, err
	}
	x.list, x.at = ps, time.Now()
	return ps, nil
}

// opener picks how keys reach the mixnet. There is no third option: without
// a proxy or the Nym binary, nymkeys refuses to run.
func (c *common) opener() (refresh.Opener, string) {
	roots, trace := c.roots(), c.tracer()
	if *c.proxy != "" {
		p, err := mixnet.ParseProxy(*c.proxy)
		if err != nil {
			die(err)
		}
		s := &sharedSession{client: source.NewClient(p, roots, trace), desc: "shared Nym client " + p}
		return func(ctx context.Context) (refresh.Session, error) {
			return &sharedSession{client: s.client, desc: s.desc}, nil
		}, "one shared Nym client at " + p + " (the exit can link these requests; drop --proxy for a new client per key)"
	}
	bin, err := nym.FindBinary(*c.binary)
	if err != nil {
		die(fmt.Errorf("%v\n(or use --proxy HOST:PORT with a running nym-socks5-client)", err))
	}
	cache := &exitCache{minPerf: *c.minPerf}
	return func(ctx context.Context) (refresh.Session, error) {
		ps, err := cache.get()
		if err != nil {
			return nil, err
		}
		var last error
		for attempt := 0; attempt < 3; attempt++ {
			p, err := nym.PickProvider(ps)
			if err != nil {
				return nil, err
			}
			e, err := nym.StartEphemeral(ctx, bin, p, "")
			if err != nil {
				last = err
				if ctx.Err() != nil {
					break
				}
				continue
			}
			if trace != nil {
				trace("new nym-socks5-client on %s, exit %s, up in %.1fs", e.Proxy, exitName(p), e.Startup.Seconds())
			}
			return &ephSession{e: e, client: source.NewClient(e.Proxy, roots, trace)}, nil
		}
		return nil, last
	}, "a new Nym client and a random exit gateway for every key"
}

func signalContext() (context.Context, context.CancelFunc) {
	return signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
}

// ---------------------------------------------------------------- list

func cmdList(args []string) {
	c := newCommon("list", "vks,wkd")
	parse(c.fs, args)
	keys, err := c.gpg().List()
	if err != nil {
		die(err)
	}
	if *c.jsonOut {
		b, _ := json.MarshalIndent(keys, "", "  ")
		fmt.Println(string(b))
		return
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "FINGERPRINT\tSTATE\tEXPIRES\tUID\tWKD DOMAINS")
	for _, k := range keys {
		state := "ok"
		switch k.Validity {
		case "r":
			state = "revoked"
		case "e":
			state = "expired"
		}
		exp := "-"
		if !k.Expires.IsZero() {
			exp = k.Expires.Format("2006-01-02")
		}
		uid := ""
		if len(k.UIDs) > 0 {
			uid = k.UIDs[0]
			if len(uid) > 40 {
				uid = uid[:39] + "…"
			}
		}
		var doms []string
		for _, e := range k.Emails {
			if _, d, err := wkd.Split(e); err == nil && !contains(doms, d) {
				doms = append(doms, d)
			}
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", k.Fingerprint, state, exp, uid, strings.Join(doms, ","))
	}
	tw.Flush()
	fmt.Fprintf(os.Stderr, "%d keys\n", len(keys))
}

func contains(xs []string, x string) bool {
	for _, y := range xs {
		if y == x {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------- refresh / daemon

func cmdRefresh(args []string, daemon bool) {
	name := "refresh"
	if daemon {
		name = "daemon"
	}
	c := newCommon(name, "vks,wkd")
	over := c.fs.Duration("over", time.Hour, "refresh: spread the keys over about this long (random gaps)")
	now := c.fs.Bool("now", false, "refresh: no gaps (the keyserver sees the requests close together in time)")
	period := c.fs.Duration("period", 7*24*time.Hour, "daemon: on average each key is refreshed once per period")
	withRevoked := c.fs.Bool("include-revoked", false, "also refresh keys that are already revoked")
	pos := parse(c.fs, args)

	srcs, err := source.Parse(*c.sources, *c.keyserver, *c.hkp)
	if err != nil {
		die(err)
	}
	open, how := c.opener()
	r := &refresh.Refresher{GPG: c.gpg(), Sources: srcs, Open: open, MaxBytes: *c.maxBytes,
		Timeout: *c.timeout, Retries: *c.retries, DryRun: *c.dryRun}
	ctx, cancel := signalContext()
	defer cancel()
	rng := rand.New(rand.NewPCG(rand.Uint64(), rand.Uint64()))
	stamp := func() string { return time.Now().Format("2006-01-02 15:04:05") }
	printRes := func(res *refresh.Result) {
		if *c.jsonOut {
			b, _ := json.Marshal(res)
			fmt.Println(string(b))
			return
		}
		fmt.Printf("%s  %s\n", stamp(), res.Line())
		if res.Via != "" {
			fmt.Printf("%21s via %s\n", "", res.Via)
		}
		for _, s := range res.Sources {
			if !s.OK && s.Error != "" && s.Error != source.ErrNotFound.Error() && s.Error != source.ErrSkipped.Error() && *c.verbose {
				fmt.Printf("%21s %s: %s\n", "", s.Source, s.Error)
			}
		}
	}

	if daemon {
		if len(pos) > 0 {
			die(errors.New("daemon takes no fingerprints; it refreshes the whole keyring"))
		}
		r.IncludeRevoked = *withRevoked
		fmt.Fprintf(os.Stderr, "nymkeys daemon: each key about once per %s, random order and times, %s\n", *period, how)
		err := r.Daemon(ctx, *period, rng, refresh.RealSleep, func(wait time.Duration, res *refresh.Result) {
			if res == nil {
				if *c.verbose {
					fmt.Fprintf(os.Stderr, "%s  next refresh in %s\n", stamp(), wait.Round(time.Second))
				}
				return
			}
			printRes(res)
		})
		if err != nil && !errors.Is(err, context.Canceled) {
			die(err)
		}
		return
	}

	keys, err := c.gpg().List()
	if err != nil {
		die(err)
	}
	keys, err = selectKeys(keys, pos, *withRevoked)
	if err != nil {
		die(err)
	}
	if len(keys) == 0 {
		fmt.Fprintln(os.Stderr, "no keys to refresh")
		return
	}
	window := *over
	if *now {
		window = 0
	}
	if window == 0 && len(keys) > 1 {
		fmt.Fprintln(os.Stderr, "note: --now sends the requests back to back; a keyserver can link them by time. Use --over for real use.")
	}
	fmt.Fprintf(os.Stderr, "refreshing %d key(s) in random order over ~%s from %s; %s\n",
		len(keys), window, *c.sources, how)
	results := r.Batch(ctx, keys, window, rng, refresh.RealSleep, func(i int, wait time.Duration, res *refresh.Result) {
		if res == nil {
			if wait > 0 && !*c.jsonOut {
				fmt.Fprintf(os.Stderr, "%s  [%d/%d] next in %s\n", stamp(), i+1, len(keys), wait.Round(time.Second))
			}
			return
		}
		printRes(res)
	})
	counts := map[string]int{}
	for _, res := range results {
		counts[res.Outcome]++
	}
	var parts []string
	for _, o := range []string{"updated", "unchanged", "checked", "not-found", "rejected", "failed"} {
		if counts[o] > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", counts[o], o))
		}
	}
	fmt.Fprintf(os.Stderr, "done: %s\n", strings.Join(parts, ", "))
	if counts["failed"]+counts["rejected"] > 0 || len(results) < len(keys) {
		os.Exit(1)
	}
}

// selectKeys keeps the keys named by full fingerprint (all if none named).
func selectKeys(keys []keyring.Key, want []string, withRevoked bool) ([]keyring.Key, error) {
	if len(want) == 0 {
		var out []keyring.Key
		for _, k := range keys {
			if k.Revoked() && !withRevoked {
				continue
			}
			out = append(out, k)
		}
		return out, nil
	}
	byFpr := map[string]keyring.Key{}
	for _, k := range keys {
		byFpr[k.Fingerprint] = k
	}
	var out []keyring.Key
	for _, w := range want {
		f, err := keyring.NormFingerprint(w)
		if err != nil {
			return nil, err
		}
		k, ok := byFpr[f]
		if !ok {
			return nil, fmt.Errorf("%s is not in the keyring (use `nymkeys fetch` to add a new key)", f)
		}
		out = append(out, k)
	}
	return out, nil
}

// ---------------------------------------------------------------- fetch

func cmdFetch(args []string) {
	c := newCommon("fetch", "vks")
	var emails multi
	c.fs.Var(&emails, "email", "also ask this address's WKD (repeatable); the key must still match FPR")
	pos := parse(c.fs, args)
	if len(pos) != 1 {
		die(errors.New("usage: nymkeys fetch [--email ADDR] FINGERPRINT"))
	}
	fpr, err := keyring.NormFingerprint(pos[0])
	if err != nil {
		die(err)
	}
	if keys, err := c.gpg().List(); err == nil {
		for _, k := range keys {
			if k.Fingerprint == fpr {
				die(fmt.Errorf("%s is already in the keyring; use `nymkeys refresh %s`", fpr, fpr))
			}
		}
	}
	srcSpec := *c.sources
	if len(emails) > 0 && !strings.Contains(srcSpec, "wkd") {
		srcSpec += ",wkd"
	}
	srcs, err := source.Parse(srcSpec, *c.keyserver, *c.hkp)
	if err != nil {
		die(err)
	}
	open, how := c.opener()
	r := &refresh.Refresher{GPG: c.gpg(), Sources: srcs, Open: open, MaxBytes: *c.maxBytes,
		Timeout: *c.timeout, Retries: *c.retries, DryRun: *c.dryRun, NewKey: true}
	ctx, cancel := signalContext()
	defer cancel()
	fmt.Fprintf(os.Stderr, "fetching %s from %s; %s\n", fpr, srcSpec, how)
	var lower []string
	for _, e := range emails {
		lower = append(lower, strings.ToLower(e))
	}
	res := r.One(ctx, keyring.Key{Fingerprint: fpr, Emails: lower})
	if *c.jsonOut {
		b, _ := json.Marshal(res)
		fmt.Println(string(b))
	} else {
		if res.After != nil && len(res.After.UIDs) > 0 {
			res.Name = res.After.UIDs[0]
		}
		fmt.Println(res.Line())
		if res.Via != "" {
			fmt.Printf("  via %s\n", res.Via)
		}
	}
	if res.Outcome != "imported" && res.Outcome != "checked" {
		os.Exit(1)
	}
}

// ---------------------------------------------------------------- wkd-url

func cmdWKD(args []string) {
	if len(args) != 1 {
		die(errors.New("usage: nymkeys wkd-url ADDRESS"))
	}
	adv, direct, err := wkd.URLs(args[0])
	if err != nil {
		die(err)
	}
	fmt.Println(adv)
	fmt.Println(direct)
}

// exitName is "node 2871 (GR)", or "node 973" when the node gives no country.
func exitName(p nym.ExitProvider) string {
	if p.Country == "" {
		return fmt.Sprintf("node %d", p.NodeID)
	}
	return fmt.Sprintf("node %d (%s)", p.NodeID, p.Country)
}
