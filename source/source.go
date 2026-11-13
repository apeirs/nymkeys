// Package source fetches one public key from a keyserver or a Web Key
// Directory. It never dials anything itself: the caller hands it an
// http.Client whose transport goes through the mixnet.
package source

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/apeirs/nymkeys/keyring"
	"github.com/apeirs/nymkeys/mixnet"
	"github.com/apeirs/nymkeys/wkd"
)

// ErrNotFound means the source answered and does not have the key.
var ErrNotFound = errors.New("not found")

// ErrSkipped means the source had nothing to ask for this key (WKD: the key
// has no email address). Nothing was sent.
var ErrSkipped = errors.New("skipped")

// DefaultMaxBytes caps one answer. Real keys are a few KB to a few hundred
// KB; flooded keys (CVE-2019-13050) are megabytes.
const DefaultMaxBytes = 1 << 20

// Source is somewhere a key can be fetched from.
type Source interface {
	Name() string
	// Fetch returns the raw key material (armored or binary) for k. It may
	// make several requests (WKD tries each address of the key).
	Fetch(ctx context.Context, c *http.Client, k keyring.Key, maxBytes int64) ([]byte, error)
}

// NewClient returns an HTTP client that reaches the network only through
// the SOCKS5 proxy (nym-socks5-client): no environment proxy, no cookies,
// HTTPS only (also after redirects). roots nil = system roots.
func NewClient(proxy string, roots *x509.CertPool, trace mixnet.Tracer) *http.Client {
	d := &mixnet.Dialer{Proxy: proxy, Timeout: 60 * time.Second, Trace: trace}
	tr := &http.Transport{
		Proxy:                 nil,
		DialContext:           d.DialContext,
		TLSClientConfig:       &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout:   60 * time.Second,
		ResponseHeaderTimeout: 60 * time.Second,
		ForceAttemptHTTP2:     true,
		MaxIdleConnsPerHost:   1,
	}
	return &http.Client{
		// A whole request, body included: a stalled mixnet stream must not
		// eat the per-key time budget.
		Timeout:   90 * time.Second,
		Transport: tr,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if req.URL.Scheme != "https" {
				return fmt.Errorf("refusing redirect to %s (not https)", req.URL.Redacted())
			}
			if len(via) >= 3 {
				return errors.New("too many redirects")
			}
			return nil
		},
	}
}

// get fetches u, reads at most maxBytes, and maps 404/410 to ErrNotFound.
// It sends no User-Agent, cookies or conditional headers: nothing that would
// tell two requests apart or link them to an earlier one.
func get(ctx context.Context, c *http.Client, u string, maxBytes int64) ([]byte, error) {
	if !strings.HasPrefix(u, "https://") {
		return nil, fmt.Errorf("refusing %s: not https", u)
	}
	req, err := http.NewRequestWithContext(ctx, "GET", u, nil)
	if err != nil {
		return nil, err
	}
	req.Header["User-Agent"] = []string{""} // net/http then sends none
	req.Header.Set("Accept", "*/*")
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == 404 || resp.StatusCode == 410:
		return nil, ErrNotFound
	case resp.StatusCode != 200:
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	if maxBytes <= 0 {
		maxBytes = DefaultMaxBytes
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > maxBytes {
		return nil, fmt.Errorf("answer larger than %d bytes (flooded key?), dropped", maxBytes)
	}
	if len(b) == 0 {
		return nil, ErrNotFound
	}
	return b, nil
}

// VKS is a Verifying Keyserver (keys.openpgp.org and its software, Hagrid):
// it serves only self-signatures and only UIDs whose owner confirmed by email.
type VKS struct{ Base string }

func (v VKS) Name() string { return "vks" }

func (v VKS) base() string {
	if v.Base == "" {
		return "https://keys.openpgp.org"
	}
	return strings.TrimRight(v.Base, "/")
}

func (v VKS) Fetch(ctx context.Context, c *http.Client, k keyring.Key, maxBytes int64) ([]byte, error) {
	return get(ctx, c, v.base()+"/vks/v1/by-fingerprint/"+k.Fingerprint, maxBytes)
}

// HKP is a classic keyserver over HTTPS (Hockeypuck, e.g. keyserver.ubuntu.com).
type HKP struct{ Base string }

func (h HKP) Name() string { return "hkp" }

func (h HKP) base() string {
	if h.Base == "" {
		return "https://keyserver.ubuntu.com"
	}
	return strings.TrimRight(h.Base, "/")
}

func (h HKP) Fetch(ctx context.Context, c *http.Client, k keyring.Key, maxBytes int64) ([]byte, error) {
	q := url.Values{"op": {"get"}, "options": {"mr"}, "search": {"0x" + k.Fingerprint}}
	return get(ctx, c, h.base()+"/pks/lookup?"+q.Encode(), maxBytes)
}

// WKD asks each email domain of the key for the key (advanced method, then
// direct). A key without email addresses is ErrSkipped.
type WKD struct {
	// Rewrite, if set, maps a URL before fetching (tests point it at fakes).
	Rewrite func(string) string
	// AdvancedTimeout caps the advanced-method request (0 = 20s). Most
	// domains have no openpgpkey.<domain> host; the exit gateway resolves
	// names, and through the mixnet a name that does not resolve looks like
	// a connection that never answers, so without a cap every such domain
	// costs a full TLS timeout before the direct method is tried.
	AdvancedTimeout time.Duration
}

func (w WKD) Name() string { return "wkd" }

func (w WKD) Fetch(ctx context.Context, c *http.Client, k keyring.Key, maxBytes int64) ([]byte, error) {
	var found []byte
	var errs []string
	asked := false
	for _, addr := range k.Emails {
		adv, direct, err := wkd.URLs(addr)
		if err != nil {
			continue
		}
		asked = true
		var got []byte
		var advErr string
		for i, u := range []string{adv, direct} {
			if w.Rewrite != nil {
				u = w.Rewrite(u)
			}
			rctx, cancel := ctx, context.CancelFunc(func() {})
			if i == 0 {
				t := w.AdvancedTimeout
				if t <= 0 {
					t = 20 * time.Second
				}
				rctx, cancel = context.WithTimeout(ctx, t)
			}
			b, err := get(rctx, c, u, maxBytes)
			cancel()
			if err == nil {
				got = b
				break
			}
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			if errors.Is(err, ErrNotFound) {
				continue
			}
			msg := fmt.Sprintf("%s: %v", hostOf(u), short(err))
			if i == 0 {
				// An advanced host that does not exist is the normal case;
				// it only counts as an error if the direct method fails too.
				advErr = msg
				continue
			}
			if advErr != "" {
				errs = append(errs, advErr)
			}
			errs = append(errs, msg)
		}
		if got != nil {
			if int64(len(found)+len(got)) > maxBytes && maxBytes > 0 {
				return nil, fmt.Errorf("answers larger than %d bytes, dropped", maxBytes)
			}
			found = append(found, got...)
		}
	}
	if found != nil {
		return found, nil
	}
	if len(errs) > 0 {
		return nil, errors.New(strings.Join(errs, "; "))
	}
	if !asked {
		return nil, ErrSkipped
	}
	return nil, ErrNotFound
}

func hostOf(u string) string {
	if p, err := url.Parse(u); err == nil {
		return p.Host
	}
	return u
}

// short trims Go's wrapped error chains to their last useful part.
func short(err error) string {
	s := err.Error()
	if i := strings.LastIndex(s, ": SOCKS5 "); i >= 0 {
		return s[i+2:]
	}
	if len(s) > 160 {
		s = s[:160] + "..."
	}
	return s
}

// Parse turns a comma-separated list ("vks,wkd,hkp") into sources.
func Parse(list, vksBase, hkpBase string) ([]Source, error) {
	var out []Source
	seen := map[string]bool{}
	for _, n := range strings.Split(list, ",") {
		n = strings.TrimSpace(strings.ToLower(n))
		if n == "" || seen[n] {
			continue
		}
		seen[n] = true
		switch n {
		case "vks":
			out = append(out, VKS{Base: vksBase})
		case "hkp":
			out = append(out, HKP{Base: hkpBase})
		case "wkd":
			out = append(out, WKD{})
		default:
			return nil, fmt.Errorf("unknown source %q (vks, wkd, hkp)", n)
		}
	}
	if len(out) == 0 {
		return nil, errors.New("no sources")
	}
	return out, nil
}
