package refresh

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/apeirs/nymkeys/internal/fakes"
	"github.com/apeirs/nymkeys/internal/testkeys"
	"github.com/apeirs/nymkeys/keyring"
	"github.com/apeirs/nymkeys/source"
)

var fx *testkeys.Set

func TestMain(m *testing.M) {
	var err error
	fx, err = testkeys.Make()
	if err != nil {
		fx.Cleanup()
		fmt.Fprintln(os.Stderr, "fixtures:", err)
		os.Exit(1)
	}
	code := m.Run()
	fx.Cleanup()
	os.Exit(code)
}

// keyserver is a fake VKS + WKD host set behind a fake nym-socks5-client.
type keyserver struct {
	ca    *fakes.CA
	socks *fakes.SOCKS
	mu    sync.Mutex
	vks   map[string][]byte // fpr -> answer
	wkd   map[string][]byte // path -> answer
	hits  atomic.Int64
	uas   []string
}

func newKeyserver(t *testing.T) *keyserver {
	ks := &keyserver{ca: fakes.NewCA(), vks: map[string][]byte{}, wkd: map[string][]byte{}}
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ks.hits.Add(1)
		ks.mu.Lock()
		ks.uas = append(ks.uas, r.Header.Get("User-Agent"))
		var body []byte
		var ok bool
		if strings.HasPrefix(r.URL.Path, "/vks/v1/by-fingerprint/") {
			body, ok = ks.vks[strings.TrimPrefix(r.URL.Path, "/vks/v1/by-fingerprint/")]
		} else {
			body, ok = ks.wkd[r.Host+r.URL.Path]
		}
		ks.mu.Unlock()
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Write(body)
	})
	routes := map[string]string{}
	for _, host := range []string{"keys.openpgp.org", "openpgpkey.example.org", "example.net"} {
		srv := httptest.NewUnstartedServer(h)
		srv.TLS = tlsWith(ks.ca.Leaf(host))
		srv.StartTLS()
		t.Cleanup(srv.Close)
		routes[host+":443"] = srv.Listener.Addr().String()
	}
	ks.socks = fakes.NewSOCKS(routes)
	t.Cleanup(ks.socks.Close)
	return ks
}

func (ks *keyserver) set(fpr string, data []byte) {
	ks.mu.Lock()
	defer ks.mu.Unlock()
	ks.vks[fpr] = data
}

type testSession struct{ c *http.Client }

func (s testSession) Client() *http.Client { return s.c }
func (s testSession) Describe() string     { return "test" }
func (s testSession) Close()               {}

func (ks *keyserver) refresher(t *testing.T, home string, srcs ...source.Source) (*Refresher, *atomic.Int64) {
	if len(srcs) == 0 {
		srcs = []source.Source{source.VKS{}}
	}
	var opened atomic.Int64
	r := &Refresher{
		GPG:     keyring.GPG{Home: home},
		Sources: srcs,
		Timeout: 30 * time.Second,
		Open: func(ctx context.Context) (Session, error) {
			opened.Add(1)
			return testSession{source.NewClient(ks.socks.Addr, ks.ca.Pool, nil)}, nil
		},
	}
	return r, &opened
}

func localHome(t *testing.T, data ...[]byte) string {
	t.Helper()
	h, err := testkeys.NewHome(t.TempDir(), "g")
	if err != nil {
		t.Fatal(err)
	}
	if err := testkeys.Import(h, data...); err != nil {
		t.Fatal(err)
	}
	return h
}

func key(t *testing.T, home, fpr string) keyring.Key {
	t.Helper()
	keys, err := keyring.GPG{Home: home}.List()
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range keys {
		if k.Fingerprint == fpr {
			return k
		}
	}
	t.Fatalf("%s not in %s", fpr, home)
	return keyring.Key{}
}

func TestUpdateMergesNewSubkeyAndExpiry(t *testing.T) {
	ks := newKeyserver(t)
	ks.set(fx.Alice, fx.AliceNew)
	home := localHome(t, fx.AliceOld)
	before := key(t, home, fx.Alice)
	r, opened := ks.refresher(t, home)
	res := r.One(context.Background(), before)
	if res.Outcome != "updated" {
		t.Fatalf("outcome %s: %s", res.Outcome, res.Detail)
	}
	after := key(t, home, fx.Alice)
	if after.Subkeys != before.Subkeys+1 || !after.Expires.After(before.Expires) {
		t.Fatalf("not merged: before %+v after %+v", before, after)
	}
	if !strings.Contains(res.Detail, "+1 subkey") || !strings.Contains(res.Detail, "expires ") {
		t.Errorf("detail %q", res.Detail)
	}
	if opened.Load() != 1 {
		t.Errorf("sessions opened: %d", opened.Load())
	}
	// Second time: nothing new.
	res = r.One(context.Background(), after)
	if res.Outcome != "unchanged" {
		t.Errorf("second refresh: %s %s", res.Outcome, res.Detail)
	}
}

func TestRevocationArrives(t *testing.T) {
	ks := newKeyserver(t)
	ks.set(fx.Carol, fx.CarolRevoked)
	home := localHome(t, fx.CarolOld)
	r, _ := ks.refresher(t, home)
	res := r.One(context.Background(), key(t, home, fx.Carol))
	if res.Outcome != "updated" || !strings.Contains(res.Detail, "NOW REVOKED") {
		t.Fatalf("%s %s", res.Outcome, res.Detail)
	}
	if !key(t, home, fx.Carol).Revoked() {
		t.Fatal("not revoked locally")
	}
}

func TestThirdPartyCertificationsDropped(t *testing.T) {
	ks := newKeyserver(t)
	ks.set(fx.Alice, fx.AliceCertified)
	home := localHome(t, fx.AliceNew, fx.BobKey)
	r, _ := ks.refresher(t, home)
	res := r.One(context.Background(), key(t, home, fx.Alice))
	if res.Outcome != "unchanged" {
		t.Fatalf("Mallory's certification was imported: %s %s", res.Outcome, res.Detail)
	}
	out, err := runGPG(home, "--list-sigs", fx.Alice)
	if err != nil || !strings.Contains(out, "sig:") {
		t.Fatalf("list-sigs: %v", err)
	}
	if strings.Contains(out, fx.Mallory[24:]) {
		t.Fatal("Mallory's signature is in the keyring")
	}
}

func runGPG(home string, args ...string) (string, error) {
	out, err := exec.Command("gpg", append([]string{"--homedir", home, "--batch", "--with-colons"}, args...)...).Output()
	return string(out), err
}

func tlsWith(cert tls.Certificate) *tls.Config {
	return &tls.Config{Certificates: []tls.Certificate{cert}}
}

func TestWrongKeyRejected(t *testing.T) {
	ks := newKeyserver(t)
	ks.set(fx.Alice, fx.BobKey) // the server answers with someone else's key
	home := localHome(t, fx.AliceOld)
	r, _ := ks.refresher(t, home)
	before := key(t, home, fx.Alice)
	res := r.One(context.Background(), before)
	if res.Outcome != "rejected" || !strings.Contains(res.Detail, "does not contain the requested key") {
		t.Fatalf("%s %s", res.Outcome, res.Detail)
	}
	keys, _ := keyring.GPG{Home: home}.List()
	if len(keys) != 1 {
		t.Fatalf("keyring now has %d keys", len(keys))
	}
}

func TestExtraKeysRejected(t *testing.T) {
	ks := newKeyserver(t)
	ks.set(fx.Alice, append(append([]byte{}, fx.AliceNew...), fx.BobKey...))
	home := localHome(t, fx.AliceOld, fx.BobKey)
	r, _ := ks.refresher(t, home)
	before := key(t, home, fx.Alice)
	res := r.One(context.Background(), before)
	if res.Outcome != "rejected" || !strings.Contains(res.Detail, "other keys") {
		t.Fatalf("%s %s", res.Outcome, res.Detail)
	}
	if key(t, home, fx.Alice).Subkeys != before.Subkeys {
		t.Fatal("rejected answer was merged")
	}
}

func TestSecretKeyNeverAccepted(t *testing.T) {
	ks := newKeyserver(t)
	ks.set(fx.Alice, fx.AliceSecret)
	home := localHome(t, fx.AliceOld)
	r, _ := ks.refresher(t, home)
	res := r.One(context.Background(), key(t, home, fx.Alice))
	if res.Outcome != "rejected" {
		t.Fatalf("%s %s", res.Outcome, res.Detail)
	}
	if _, err := os.Stat(home + "/private-keys-v1.d"); err == nil {
		entries, _ := os.ReadDir(home + "/private-keys-v1.d")
		if len(entries) > 0 {
			t.Fatal("a secret key reached the keyring")
		}
	}
}

func TestOversizeDropped(t *testing.T) {
	ks := newKeyserver(t)
	ks.set(fx.Alice, fx.AliceNew)
	home := localHome(t, fx.AliceOld)
	r, _ := ks.refresher(t, home)
	r.MaxBytes = int64(len(fx.AliceNew) - 1)
	before := key(t, home, fx.Alice)
	res := r.One(context.Background(), before)
	if res.Outcome != "failed" || !strings.Contains(res.Sources[0].Error, "larger than") {
		t.Fatalf("%s %+v", res.Outcome, res.Sources)
	}
	if key(t, home, fx.Alice).Subkeys != before.Subkeys {
		t.Fatal("oversize answer merged")
	}
}

func TestNotFound(t *testing.T) {
	ks := newKeyserver(t)
	home := localHome(t, fx.AliceOld)
	r, _ := ks.refresher(t, home)
	res := r.One(context.Background(), key(t, home, fx.Alice))
	if res.Outcome != "not-found" {
		t.Fatalf("%s %s", res.Outcome, res.Detail)
	}
}

func TestDryRunImportsNothing(t *testing.T) {
	ks := newKeyserver(t)
	ks.set(fx.Alice, fx.AliceNew)
	home := localHome(t, fx.AliceOld)
	r, _ := ks.refresher(t, home)
	r.DryRun = true
	before := key(t, home, fx.Alice)
	if res := r.One(context.Background(), before); res.Outcome != "checked" {
		t.Fatalf("%s %s", res.Outcome, res.Detail)
	}
	if key(t, home, fx.Alice).Subkeys != before.Subkeys {
		t.Fatal("dry run merged")
	}
}

func TestMergeOnlyNeverAddsKeys(t *testing.T) {
	// A refresh of Alice with Bob's key as the "answer" is rejected by Check;
	// and even calling Merge directly with Bob's key must not add him.
	home := localHome(t, fx.AliceOld)
	if _, err := (keyring.GPG{Home: home}).Merge(fx.BobKey); err != nil {
		t.Fatal(err)
	}
	keys, _ := keyring.GPG{Home: home}.List()
	if len(keys) != 1 {
		t.Fatalf("merge-only added a key: %d keys", len(keys))
	}
}

func TestOnlyMixnetNamesNoUserAgent(t *testing.T) {
	ks := newKeyserver(t)
	ks.set(fx.Alice, fx.AliceNew)
	ks.mu.Lock()
	ks.wkd["example.net/.well-known/openpgpkey/hu/"+bobHash()] = fx.BobKey
	ks.mu.Unlock()
	home := localHome(t, fx.AliceOld, fx.BobKey)
	r, _ := ks.refresher(t, home, source.VKS{}, source.WKD{})
	for _, fpr := range []string{fx.Alice, fx.Bob} {
		if res := r.One(context.Background(), key(t, home, fpr)); res.Outcome == "failed" || res.Outcome == "rejected" {
			t.Fatalf("%s: %s %s", fpr, res.Outcome, res.Detail)
		}
	}
	seen := ks.socks.Seen()
	if len(seen) == 0 {
		t.Fatal("nothing went through the SOCKS proxy")
	}
	var hosts []string
	for _, s := range seen {
		if s.ATYP != 3 {
			t.Errorf("CONNECT with ATYP %d (a locally resolved address): %v", s.ATYP, s)
		}
		hosts = append(hosts, s.Host)
	}
	joined := strings.Join(hosts, " ")
	// Bob's domain has no openpgpkey. host (unreachable), so the direct method was used.
	for _, want := range []string{"keys.openpgp.org", "openpgpkey.example.org", "openpgpkey.example.net", "example.net"} {
		if !strings.Contains(" "+joined+" ", " "+want+" ") {
			t.Errorf("expected a CONNECT to %s, saw %s", want, joined)
		}
	}
	for _, ua := range ks.uas {
		if ua != "" {
			t.Errorf("User-Agent sent: %q", ua)
		}
	}
}

func bobHash() string {
	// z-base-32 SHA-1 of "bob", as gpg-wks-client --print-wkd-hash prints it.
	return "jycbiujnsxs47xrkethgtj69xuunurok"
}

func TestNoProxyNoFallback(t *testing.T) {
	ks := newKeyserver(t)
	ks.set(fx.Alice, fx.AliceNew)
	home := localHome(t, fx.AliceOld)
	// A port nothing listens on.
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	dead := ln.Addr().String()
	ln.Close()
	r := &Refresher{GPG: keyring.GPG{Home: home}, Sources: []source.Source{source.VKS{}}, Timeout: 10 * time.Second,
		Open: func(ctx context.Context) (Session, error) {
			return testSession{source.NewClient(dead, ks.ca.Pool, nil)}, nil
		}}
	res := r.One(context.Background(), key(t, home, fx.Alice))
	if res.Outcome != "failed" || !strings.Contains(res.Sources[0].Error, "refusing to fall back") {
		t.Fatalf("%s %+v", res.Outcome, res.Sources)
	}
	if ks.hits.Load() != 0 {
		t.Fatal("a server was reached without the proxy")
	}
	// A key with no email: WKD has nothing to ask, VKS can't be reached.
	// That is a failure, not "not found".
	r.Sources = []source.Source{source.VKS{}, source.WKD{}}
	k := key(t, home, fx.Alice)
	k.Emails = nil
	if res := r.One(context.Background(), k); res.Outcome != "failed" {
		t.Fatalf("no email, no proxy: %s %+v", res.Outcome, res.Sources)
	}
}

// A stalled route: the first session reaches nothing, the retry gets a new
// session and succeeds. Without Retries, the key just fails.
func TestRetryUsesANewSession(t *testing.T) {
	ks := newKeyserver(t)
	ks.set(fx.Alice, fx.AliceNew)
	home := localHome(t, fx.AliceOld)
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	dead := ln.Addr().String()
	ln.Close()
	var opened atomic.Int64
	r := &Refresher{GPG: keyring.GPG{Home: home}, Sources: []source.Source{source.VKS{}}, Timeout: 10 * time.Second, Retries: 1,
		Open: func(ctx context.Context) (Session, error) {
			if opened.Add(1) == 1 {
				return testSession{source.NewClient(dead, ks.ca.Pool, nil)}, nil
			}
			return testSession{source.NewClient(ks.socks.Addr, ks.ca.Pool, nil)}, nil
		}}
	res := r.One(context.Background(), key(t, home, fx.Alice))
	if res.Outcome != "updated" || res.Attempts != 2 || opened.Load() != 2 {
		t.Fatalf("%s after %d attempts, %d sessions: %s", res.Outcome, res.Attempts, opened.Load(), res.Detail)
	}
	// "not found" is an answer: no retry.
	home2 := localHome(t, fx.BobKey)
	opened.Store(1)
	res = r.One(context.Background(), key(t, home2, fx.Bob))
	if res.Outcome != "not-found" || res.Attempts != 1 {
		t.Fatalf("not found: %s after %d attempts", res.Outcome, res.Attempts)
	}
}

func TestSessionFailure(t *testing.T) {
	home := localHome(t, fx.AliceOld)
	r := &Refresher{GPG: keyring.GPG{Home: home}, Sources: []source.Source{source.VKS{}},
		Open: func(ctx context.Context) (Session, error) { return nil, errors.New("no exit gateways") }}
	res := r.One(context.Background(), key(t, home, fx.Alice))
	if res.Outcome != "failed" || !strings.Contains(res.Detail, "no exit gateways") {
		t.Fatalf("%s %s", res.Outcome, res.Detail)
	}
}

func TestRedirectToHTTPRefused(t *testing.T) {
	ca := fakes.NewCA()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://keys.openpgp.org/elsewhere", http.StatusFound)
	}))
	srv.TLS = tlsWith(ca.Leaf("keys.openpgp.org"))
	srv.StartTLS()
	defer srv.Close()
	socks := fakes.NewSOCKS(map[string]string{"keys.openpgp.org:443": srv.Listener.Addr().String()})
	defer socks.Close()
	c := source.NewClient(socks.Addr, ca.Pool, nil)
	_, err := source.VKS{}.Fetch(context.Background(), c, keyring.Key{Fingerprint: fx.Alice}, 0)
	if err == nil || !strings.Contains(err.Error(), "not https") {
		t.Fatalf("err = %v", err)
	}
	for _, s := range socks.Seen() {
		if s.Port != 443 {
			t.Fatalf("followed the redirect to port %d", s.Port)
		}
	}
}

// ---------------------------------------------------------------- timing

func TestGapsArePoisson(t *testing.T) {
	rng := rand.New(rand.NewPCG(1, 2))
	const n = 20000
	window := 100 * time.Hour
	gaps := Gaps(n, window, rng)
	var sum time.Duration
	short := 0
	for _, g := range gaps {
		sum += g
		if g < window/n/10 {
			short++
		}
	}
	mean := float64(sum) / n
	want := float64(window) / n
	if mean < want*0.95 || mean > want*1.05 {
		t.Errorf("mean gap %v, want about %v", time.Duration(mean), time.Duration(want))
	}
	// P(X < mean/10) = 1 - e^-0.1 ≈ 9.5% for an exponential.
	if f := float64(short) / n; f < 0.08 || f > 0.11 {
		t.Errorf("fraction of very short gaps %.3f, want about 0.095", f)
	}
	for _, g := range Gaps(5, 0, rng) {
		if g != 0 {
			t.Fatal("window 0 must give no waits")
		}
	}
}

func TestBatchRandomOrderOneSessionPerKey(t *testing.T) {
	ks := newKeyserver(t)
	ks.set(fx.Alice, fx.AliceNew)
	ks.set(fx.Bob, fx.BobKey)
	home := localHome(t, fx.AliceOld, fx.BobKey)
	r, opened := ks.refresher(t, home)
	keys, _ := r.GPG.List()
	var slept []time.Duration
	sleep := func(ctx context.Context, d time.Duration) error { slept = append(slept, d); return nil }
	firsts := map[string]int{}
	for i := 0; i < 8; i++ {
		res := r.Batch(context.Background(), keys, time.Hour, rand.New(rand.NewPCG(uint64(i), 7)), sleep, nil)
		if len(res) != 2 {
			t.Fatalf("results %d", len(res))
		}
		firsts[res[0].Fingerprint]++
	}
	if len(firsts) != 2 {
		t.Errorf("order never changed across seeds: %v", firsts)
	}
	if opened.Load() != 16 {
		t.Errorf("sessions %d, want one per key (16)", opened.Load())
	}
	if len(slept) != 16 || slept[0] == 0 {
		t.Errorf("sleeps %v", slept)
	}
}

func TestDaemonSleepsBeforeEachRefresh(t *testing.T) {
	ks := newKeyserver(t)
	ks.set(fx.Alice, fx.AliceNew)
	ks.set(fx.Bob, fx.BobKey)
	home := localHome(t, fx.AliceOld, fx.BobKey, fx.CarolRevoked)
	r, opened := ks.refresher(t, home)
	ctx, cancel := context.WithCancel(context.Background())
	var events []string
	var carol int
	sleeps := 0
	sleep := func(ctx context.Context, d time.Duration) error {
		sleeps++
		if sleeps > 4 {
			cancel()
			return ctx.Err()
		}
		return nil
	}
	err := r.Daemon(ctx, 24*time.Hour, rand.New(rand.NewPCG(3, 4)), sleep, func(w time.Duration, res *Result) {
		if res == nil {
			events = append(events, "sleep")
		} else {
			events = append(events, "refresh")
			if res.Fingerprint == fx.Carol {
				carol++
			}
		}
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err %v", err)
	}
	want := "sleep refresh sleep refresh sleep refresh sleep refresh sleep"
	if got := strings.Join(events, " "); got != want {
		t.Fatalf("events\n got %s\nwant %s", got, want)
	}
	if opened.Load() != 4 {
		t.Errorf("sessions %d", opened.Load())
	}
	if carol > 0 {
		t.Errorf("the revoked key was refreshed %d times", carol)
	}
}

// Through the mixnet, a WKD advanced host that does not exist looks like a
// connection that never answers (the exit resolves the name, the local client
// has already said "connected"). That must cost AdvancedTimeout, not a TLS
// timeout, and must not be reported as an error when the direct method works.
func TestWKDAdvancedBlackholeFallsBackFast(t *testing.T) {
	ks := newKeyserver(t)
	hole, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer hole.Close()
	go func() {
		for {
			c, err := hole.Accept()
			if err != nil {
				return
			}
			defer c.Close() // hold it open, never answer
		}
	}()
	ks.socks.Route("openpgpkey.example.net:443", hole.Addr().String())
	ks.mu.Lock()
	ks.wkd["example.net/.well-known/openpgpkey/hu/"+bobHash()] = fx.BobKey
	ks.mu.Unlock()
	home := localHome(t, fx.BobKey)
	r, _ := ks.refresher(t, home, source.WKD{AdvancedTimeout: 300 * time.Millisecond})
	t0 := time.Now()
	res := r.One(context.Background(), key(t, home, fx.Bob))
	if took := time.Since(t0); took > 10*time.Second {
		t.Errorf("took %v; the advanced timeout was not applied", took)
	}
	if res.Outcome != "unchanged" {
		t.Fatalf("outcome %s %s", res.Outcome, res.Detail)
	}
	if len(res.Sources) != 1 || !res.Sources[0].OK || res.Sources[0].Error != "" {
		t.Errorf("wkd source: %+v", res.Sources)
	}
	// Dead advanced host, and the direct method says 404: "not found", not an error.
	ks.mu.Lock()
	delete(ks.wkd, "example.net/.well-known/openpgpkey/hu/"+bobHash())
	ks.mu.Unlock()
	res = r.One(context.Background(), key(t, home, fx.Bob))
	if res.Outcome != "not-found" || res.Sources[0].Error != source.ErrNotFound.Error() {
		t.Errorf("after 404: %s %+v", res.Outcome, res.Sources)
	}
}
