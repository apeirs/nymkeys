// Package refresh updates keys one at a time, each through its own mixnet
// session, at random times.
//
// The privacy problem it solves: `gpg --refresh-keys` sends the fingerprint of
// every key you hold to one keyserver in one burst. Even through an anonymity
// network, a burst from one client is one keyring, and a keyring is a social
// graph. So nymkeys asks for one key per session (a fresh Nym client and exit
// gateway each time), with memoryless random gaps between keys, which is what
// parcimonie does over Tor.
package refresh

import (
	"context"
	"errors"
	"fmt"
	"math"
	"math/rand/v2"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/apeirs/nymkeys/keyring"
	"github.com/apeirs/nymkeys/source"
)

// Session is one way out through the mixnet, used for one key and closed.
type Session interface {
	Client() *http.Client
	Describe() string // e.g. "new Nym client, exit 2917 (FI), ready in 2.1s"
	Close()
}

// Opener opens a session for one key.
type Opener func(ctx context.Context) (Session, error)

// Refresher holds what every refresh needs.
type Refresher struct {
	GPG      keyring.GPG
	Sources  []source.Source
	Open     Opener
	MaxBytes int64
	Timeout  time.Duration // per key and attempt, session setup included
	DryRun   bool          // fetch and check, don't import
	NewKey   bool          // `fetch`: the key is not in the keyring yet
	// Retries is how many more times a key is tried, each with a new
	// session (a new Nym client and exit, unless the session is a shared
	// proxy), when no source answered at all: a mixnet route can stall.
	Retries int
	// IncludeRevoked makes Daemon refresh revoked keys too (Batch gets its
	// key list from the caller).
	IncludeRevoked bool
}

// SourceResult is what one source returned for one key.
type SourceResult struct {
	Source string `json:"source"`
	Bytes  int    `json:"bytes,omitempty"`
	Error  string `json:"error,omitempty"`
	OK     bool   `json:"ok"`
}

// Result of refreshing one key.
type Result struct {
	Fingerprint string               `json:"fingerprint"`
	Name        string               `json:"name,omitempty"`
	Via         string               `json:"via,omitempty"`
	Sources     []SourceResult       `json:"sources"`
	Outcome     string               `json:"outcome"` // updated, unchanged, not-found, rejected, failed, checked
	Detail      string               `json:"detail,omitempty"`
	Merge       *keyring.MergeResult `json:"merge,omitempty"`
	Before      *keyring.Key         `json:"-"`
	After       *keyring.Key         `json:"-"`
	Took        time.Duration        `json:"took_ns"`
	Changes     []string             `json:"changes,omitempty"`
	Attempts    int                  `json:"attempts"`
	retry       bool                 // nothing answered; worth another session
}

// Line is a one-line human summary.
func (r Result) Line() string {
	var srcs []string
	for _, s := range r.Sources {
		switch {
		case s.OK:
			srcs = append(srcs, fmt.Sprintf("%s %s", s.Source, kb(s.Bytes)))
		case s.Error == source.ErrNotFound.Error():
			srcs = append(srcs, s.Source+" none")
		case s.Error == source.ErrSkipped.Error():
			srcs = append(srcs, s.Source+" -")
		default:
			srcs = append(srcs, s.Source+" error")
		}
	}
	name := r.Name
	if len(name) > 32 {
		name = name[:31] + "…"
	}
	out := fmt.Sprintf("%-16s  %-32s  %-9s", short(r.Fingerprint), name, r.Outcome)
	if r.Detail != "" {
		out += "  " + r.Detail
	}
	tries := ""
	if r.Attempts > 1 {
		tries = fmt.Sprintf(", %d tries", r.Attempts)
	}
	out += fmt.Sprintf("  [%s; %.1fs%s]", strings.Join(srcs, ", "), r.Took.Seconds(), tries)
	return out
}

func short(fpr string) string {
	if len(fpr) > 16 {
		return fpr[len(fpr)-16:]
	}
	return fpr
}

func kb(n int) string {
	if n < 1024 {
		return fmt.Sprintf("%d B", n)
	}
	return fmt.Sprintf("%.0f KB", float64(n)/1024)
}

// Errors a Check can return.
var (
	ErrNoKey     = errors.New("the answer does not contain the requested key")
	ErrOtherKeys = errors.New("the answer contains other keys too")
)

// Check verifies that data holds exactly the key fpr and nothing else.
func (r *Refresher) Check(fpr string, data []byte) (keyring.Key, error) {
	keys, err := r.GPG.Inspect(data)
	if err != nil {
		return keyring.Key{}, err
	}
	var hit *keyring.Key
	var others []string
	for i := range keys {
		if keys[i].Fingerprint == fpr {
			hit = &keys[i]
		} else {
			others = append(others, short(keys[i].Fingerprint))
		}
	}
	if hit == nil {
		return keyring.Key{}, fmt.Errorf("%w (got %s)", ErrNoKey, strings.Join(others, ", "))
	}
	if len(others) > 0 {
		return keyring.Key{}, fmt.Errorf("%w: %s", ErrOtherKeys, strings.Join(others, ", "))
	}
	return *hit, nil
}

// One refreshes key k: open a session, ask every source, check every answer,
// merge the good ones, close the session.
func (r *Refresher) One(ctx context.Context, k keyring.Key) Result {
	t0 := time.Now()
	var res Result
	for attempt := 1; ; attempt++ {
		res = r.one(ctx, k)
		res.Attempts = attempt
		if !res.retry || attempt > r.Retries || ctx.Err() != nil {
			break
		}
	}
	res.Took = time.Since(t0)
	return res
}

func (r *Refresher) one(ctx context.Context, k keyring.Key) Result {
	res := Result{Fingerprint: k.Fingerprint, Before: &k}
	if len(k.UIDs) > 0 {
		res.Name = k.UIDs[0]
	}
	timeout := r.Timeout
	if timeout <= 0 {
		timeout = 3 * time.Minute
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	sess, err := r.Open(ctx)
	if err != nil {
		res.Outcome, res.Detail, res.retry = "failed", "no mixnet session: "+err.Error(), true
		return res
	}
	defer sess.Close()
	res.Via = sess.Describe()
	client := sess.Client()

	var good [][]byte
	anyAnswer := false
	var rejects []string
	for _, src := range r.Sources {
		sr := SourceResult{Source: src.Name()}
		data, err := src.Fetch(ctx, client, k, r.MaxBytes)
		switch {
		case errors.Is(err, source.ErrSkipped):
			sr.Error = source.ErrSkipped.Error()
		case errors.Is(err, source.ErrNotFound):
			sr.Error = source.ErrNotFound.Error()
			anyAnswer = true
		case err != nil:
			sr.Error = err.Error()
		default:
			anyAnswer = true
			sr.Bytes = len(data)
			if _, cerr := r.Check(k.Fingerprint, data); cerr != nil {
				sr.Error = "rejected: " + cerr.Error()
				rejects = append(rejects, src.Name()+": "+cerr.Error())
			} else {
				sr.OK = true
				good = append(good, data)
			}
		}
		res.Sources = append(res.Sources, sr)
	}

	switch {
	case len(good) == 0 && len(rejects) > 0:
		res.Outcome, res.Detail = "rejected", strings.Join(rejects, "; ")
		return res
	case len(good) == 0 && anyAnswer:
		res.Outcome = "not-found"
		return res
	case len(good) == 0:
		res.Outcome, res.Detail, res.retry = "failed", "no source answered", true
		for _, s := range res.Sources {
			if s.Error != source.ErrSkipped.Error() {
				res.Detail += " (" + s.Source + ": " + firstLine(reURL.ReplaceAllString(s.Error, ""), 90) + ")"
				break
			}
		}
		return res
	}
	if r.DryRun {
		res.Outcome, res.Detail = "checked", "dry run, nothing imported"
		return res
	}

	merged := keyring.MergeResult{}
	for _, data := range good {
		var m keyring.MergeResult
		if r.NewKey {
			err = r.GPG.Import(data)
			m.Changed = err == nil
		} else {
			m, err = r.GPG.Merge(data)
		}
		if err != nil {
			res.Outcome, res.Detail = "failed", err.Error()
			return res
		}
		merged.Changed = merged.Changed || m.Changed
		merged.NewUIDs += m.NewUIDs
		merged.NewSubkeys += m.NewSubkeys
		merged.NewSigs += m.NewSigs
		merged.NewRevoked += m.NewRevoked
	}
	res.Merge = &merged
	if after, err := r.lookup(k.Fingerprint); err == nil {
		res.After = after
		res.Changes = Diff(k, *after, r.NewKey)
	}
	switch {
	case r.NewKey:
		res.Outcome = "imported"
	case merged.Changed || len(res.Changes) > 0:
		res.Outcome = "updated"
	default:
		res.Outcome = "unchanged"
	}
	res.Detail = strings.Join(res.Changes, ", ")
	return res
}

func (r *Refresher) lookup(fpr string) (*keyring.Key, error) {
	keys, err := r.GPG.List()
	if err != nil {
		return nil, err
	}
	for i := range keys {
		if keys[i].Fingerprint == fpr {
			return &keys[i], nil
		}
	}
	return nil, errors.New("key not in keyring")
}

// Diff describes what changed between two versions of a key.
func Diff(a, b keyring.Key, isNew bool) []string {
	if isNew {
		return []string{fmt.Sprintf("%d uids, %d subkeys", len(b.UIDs), b.Subkeys)}
	}
	var out []string
	if !a.Revoked() && b.Revoked() {
		out = append(out, "NOW REVOKED")
	}
	if !a.Expires.Equal(b.Expires) {
		switch {
		case b.Expires.IsZero():
			out = append(out, "no longer expires")
		default:
			out = append(out, "expires "+b.Expires.Format("2006-01-02"))
		}
	}
	if n := len(b.UIDs) - len(a.UIDs); n > 0 {
		out = append(out, fmt.Sprintf("+%d uid", n))
	}
	if n := b.Subkeys - a.Subkeys; n > 0 {
		out = append(out, fmt.Sprintf("+%d subkey", n))
	}
	if n := b.Signatures - a.Signatures; n > 0 {
		out = append(out, fmt.Sprintf("+%d sig", n))
	}
	return out
}

// Gaps returns n waits with exponentially distributed lengths whose mean is
// window/n (a Poisson process). The first wait is random too, so starting
// the program (at boot, say) is not followed by a request at a fixed delay.
// window 0 gives n zero waits.
func Gaps(n int, window time.Duration, rng *rand.Rand) []time.Duration {
	out := make([]time.Duration, n)
	if n == 0 || window <= 0 {
		return out
	}
	mean := float64(window) / float64(n)
	for i := range out {
		out[i] = time.Duration(Exp(rng) * mean)
	}
	return out
}

// Exp draws from an exponential distribution with mean 1, capped at 20 (a
// one-in-half-a-billion tail) so a wait can't run away.
func Exp(rng *rand.Rand) float64 {
	u := rng.Float64()
	for u == 0 {
		u = rng.Float64()
	}
	return math.Min(-math.Log(u), 20)
}

// Shuffle returns keys in random order.
func Shuffle(keys []keyring.Key, rng *rand.Rand) []keyring.Key {
	out := append([]keyring.Key(nil), keys...)
	rng.Shuffle(len(out), func(i, j int) { out[i], out[j] = out[j], out[i] })
	return out
}

// Sleeper waits for d or until ctx ends (tests replace it).
type Sleeper func(ctx context.Context, d time.Duration) error

// RealSleep is a Sleeper on the wall clock.
func RealSleep(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Batch refreshes keys in random order, waiting gaps[i] before key i.
func (r *Refresher) Batch(ctx context.Context, keys []keyring.Key, window time.Duration, rng *rand.Rand,
	sleep Sleeper, report func(i int, wait time.Duration, res *Result)) []Result {
	order := Shuffle(keys, rng)
	gaps := Gaps(len(order), window, rng)
	var out []Result
	for i, k := range order {
		if report != nil {
			report(i, gaps[i], nil)
		}
		if err := sleep(ctx, gaps[i]); err != nil {
			break
		}
		res := r.One(ctx, k)
		out = append(out, res)
		if report != nil {
			report(i, gaps[i], &res)
		}
	}
	return out
}

// Daemon refreshes forever: wait Exp(period/n), refresh one random key,
// repeat, with n read from the keyring each time (keys added later are
// included). On average each key is refreshed once per period.
func (r *Refresher) Daemon(ctx context.Context, period time.Duration, rng *rand.Rand, sleep Sleeper,
	report func(wait time.Duration, res *Result)) error {
	list := func() ([]keyring.Key, error) {
		all, err := r.GPG.List()
		if err != nil || r.IncludeRevoked {
			return all, err
		}
		var live []keyring.Key
		for _, k := range all {
			if !k.Revoked() {
				live = append(live, k)
			}
		}
		return live, nil
	}
	for {
		keys, err := list()
		if err != nil {
			return err
		}
		n := len(keys)
		if n == 0 {
			n = 1
		}
		wait := time.Duration(Exp(rng) * float64(period) / float64(n))
		if report != nil {
			report(wait, nil)
		}
		if err := sleep(ctx, wait); err != nil {
			return err
		}
		if len(keys) == 0 {
			continue
		}
		// Re-read: the keyring may have changed while we slept.
		if fresh, err := list(); err == nil && len(fresh) > 0 {
			keys = fresh
		}
		res := r.One(ctx, keys[rng.IntN(len(keys))])
		if report != nil {
			report(wait, &res)
		}
	}
}

// reURL matches the `Get "https://…": ` prefix of a net/http error; the
// cause after it is the useful part.
var reURL = regexp.MustCompile(`^Get "[^"]*": `)

// firstLine is the first line of s, at most n runes.
func firstLine(s string, n int) string {
	s, _, _ = strings.Cut(s, "\n")
	if r := []rune(s); len(r) > n {
		return string(r[:n-1]) + "…"
	}
	return s
}
