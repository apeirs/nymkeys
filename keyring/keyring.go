// Package keyring reads public keys from a GnuPG keyring and merges updates
// into it. It runs gpg locally only: every gpg call gets --no-autostart, so
// gpg never starts dirmngr (which would go to the network on its own).
package keyring

import (
	"bytes"
	"errors"
	"fmt"
	"net/mail"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// GPG runs a gpg binary on one home directory ("" = gpg's default).
type GPG struct {
	Bin  string // "" = "gpg"
	Home string
}

// Key is one public key in the keyring.
type Key struct {
	Fingerprint string    `json:"fingerprint"`
	Validity    string    `json:"validity"` // gpg field 2: r = revoked, e = expired, ...
	Expires     time.Time `json:"expires,omitempty"`
	UIDs        []string  `json:"uids"`
	Emails      []string  `json:"emails"`
	Subkeys     int       `json:"subkeys"`
	Signatures  int       `json:"signatures"`
}

// Revoked reports whether the primary key is revoked.
func (k Key) Revoked() bool { return k.Validity == "r" }

// Short is the last 16 hex digits (the long key id), for display only.
func (k Key) Short() string {
	if len(k.Fingerprint) > 16 {
		return k.Fingerprint[len(k.Fingerprint)-16:]
	}
	return k.Fingerprint
}

func (g GPG) bin() string {
	if g.Bin != "" {
		return g.Bin
	}
	return "gpg"
}

func (g GPG) args(extra ...string) []string {
	a := []string{"--batch", "--no-tty", "--no-autostart", "--no-auto-key-retrieve", "--no-auto-key-locate",
		"--with-colons", "--fixed-list-mode"}
	if g.Home != "" {
		a = append(a, "--homedir", g.Home)
	}
	return append(a, extra...)
}

func (g GPG) run(stdin []byte, extra ...string) (stdout, stderr []byte, err error) {
	cmd := exec.Command(g.bin(), g.args(extra...)...)
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	var o, e bytes.Buffer
	cmd.Stdout, cmd.Stderr = &o, &e
	err = cmd.Run()
	return o.Bytes(), e.Bytes(), err
}

var reHexFpr = regexp.MustCompile(`^[0-9A-F]{40}$|^[0-9A-F]{64}$`)

// NormFingerprint uppercases and strips spaces and a 0x prefix; it accepts
// only full v4 (40 hex) or v5/v6 (64 hex) fingerprints. Short and long key ids
// are refused: anyone can make a key with a chosen 64-bit id.
func NormFingerprint(s string) (string, error) {
	f := strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(s), " ", ""))
	f = strings.TrimPrefix(f, "0X")
	if !reHexFpr.MatchString(f) {
		return "", fmt.Errorf("%q is not a full fingerprint (40 or 64 hex digits)", s)
	}
	return f, nil
}

// List returns every public key in the keyring, sorted by fingerprint.
func (g GPG) List() ([]Key, error) {
	out, stderr, err := g.run(nil, "--list-sigs")
	if err != nil {
		// An empty or not yet created keyring is not an error.
		if len(bytes.TrimSpace(out)) == 0 && bytes.Contains(stderr, []byte("No public key")) {
			return nil, nil
		}
		if len(bytes.TrimSpace(out)) == 0 {
			return nil, fmt.Errorf("gpg --list-keys: %v: %s", err, strings.TrimSpace(string(stderr)))
		}
	}
	return ParseColons(out), nil
}

// ParseColons parses `gpg --with-colons --fixed-list-mode --list-sigs` output
// (also the output of --import-options show-only).
func ParseColons(out []byte) []Key {
	var keys []Key
	var cur *Key
	inPrimary := false // the next fpr record belongs to the primary key
	for _, line := range strings.Split(string(out), "\n") {
		f := strings.Split(strings.TrimRight(line, "\r"), ":")
		if len(f) < 2 {
			continue
		}
		switch f[0] {
		case "pub":
			keys = append(keys, Key{Validity: field(f, 1)})
			cur = &keys[len(keys)-1]
			inPrimary = true
			if exp := field(f, 6); exp != "" {
				if t, ok := parseTime(exp); ok {
					cur.Expires = t
				}
			}
		case "fpr":
			if cur != nil && inPrimary {
				cur.Fingerprint = field(f, 9)
				inPrimary = false
			}
		case "uid":
			if cur != nil {
				uid := unescape(field(f, 9))
				cur.UIDs = append(cur.UIDs, uid)
				if e := emailOf(uid); e != "" && !contains(cur.Emails, e) {
					cur.Emails = append(cur.Emails, e)
				}
			}
		case "sub":
			if cur != nil {
				cur.Subkeys++
			}
		case "sig", "rev":
			if cur != nil {
				cur.Signatures++
			}
		}
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i].Fingerprint < keys[j].Fingerprint })
	return keys
}

func field(f []string, i int) string {
	if i < len(f) {
		return f[i]
	}
	return ""
}

func parseTime(s string) (time.Time, bool) {
	if n, err := strconv.ParseInt(s, 10, 64); err == nil {
		return time.Unix(n, 0).UTC(), true
	}
	if t, err := time.Parse("20060102T150405", s); err == nil {
		return t.UTC(), true
	}
	return time.Time{}, false
}

// unescape undoes gpg's \xNN escaping in colon listings.
func unescape(s string) string {
	if !strings.Contains(s, `\x`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) && s[i+1] == 'x' {
			if n, err := strconv.ParseUint(s[i+2:i+4], 16, 8); err == nil {
				b.WriteByte(byte(n))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func emailOf(uid string) string {
	if a, err := mail.ParseAddress(uid); err == nil {
		return strings.ToLower(a.Address)
	}
	s := strings.TrimSpace(uid)
	if strings.Count(s, "@") == 1 && !strings.ContainsAny(s, " <>") {
		return strings.ToLower(s)
	}
	if i, j := strings.LastIndex(s, "<"), strings.LastIndex(s, ">"); i >= 0 && j > i {
		e := s[i+1 : j]
		if strings.Count(e, "@") == 1 {
			return strings.ToLower(e)
		}
	}
	return ""
}

func contains(xs []string, x string) bool {
	for _, y := range xs {
		if y == x {
			return true
		}
	}
	return false
}

// Inspect parses key material without importing anything and returns the
// keys it contains.
func (g GPG) Inspect(data []byte) ([]Key, error) {
	out, stderr, err := g.run(data, "--import-options", "show-only,import-show", "--import")
	keys := ParseColons(out)
	if len(keys) == 0 {
		if err == nil {
			err = errors.New("no key found")
		}
		return nil, fmt.Errorf("gpg could not parse the answer as an OpenPGP key: %v: %s", err, firstLine(stderr))
	}
	return keys, nil
}

// MergeResult is what gpg reported for one merge.
type MergeResult struct {
	Changed    bool   `json:"changed"`
	NewUIDs    int    `json:"new_uids"`
	NewSubkeys int    `json:"new_subkeys"`
	NewSigs    int    `json:"new_signatures"`
	NewRevoked int    `json:"new_revocations"`
	Status     string `json:"-"`
}

// Merge imports updates to keys already in the keyring. merge-only makes gpg
// refuse keys that are not there yet; self-sigs-only drops third-party
// certifications (the defence against certificate flooding); secret keys are
// never accepted.
func (g GPG) Merge(data []byte) (MergeResult, error) {
	out, stderr, err := g.run(data, "--status-fd", "1", "--import-options", "merge-only,self-sigs-only", "--import")
	r := MergeResult{Status: string(out)}
	for _, line := range strings.Split(string(out), "\n") {
		f := strings.Fields(line)
		if len(f) < 3 || f[0] != "[GNUPG:]" {
			continue
		}
		switch f[1] {
		case "IMPORT_OK":
			flags, _ := strconv.Atoi(f[2])
			if flags&16 != 0 {
				return r, errors.New("refusing: the answer contains a secret key")
			}
			if flags&^16 != 0 {
				r.Changed = true
			}
		case "IMPORT_RES":
			// count no_user_id imported imp_rsa unchanged n_uids n_subk n_sigs n_revoc ...
			n := func(i int) int {
				if 2+i < len(f) {
					v, _ := strconv.Atoi(f[2+i])
					return v
				}
				return 0
			}
			r.NewUIDs, r.NewSubkeys, r.NewSigs, r.NewRevoked = n(5), n(6), n(7), n(8)
			if r.NewUIDs+r.NewSubkeys+r.NewSigs+r.NewRevoked > 0 {
				r.Changed = true
			}
		}
	}
	if err != nil && !strings.Contains(r.Status, "IMPORT_RES") {
		return r, fmt.Errorf("gpg --import: %v: %s", err, firstLine(stderr))
	}
	return r, nil
}

// ErrNoUserID: the key came without any user ID, which gpg can't import as a
// new key. keys.openpgp.org serves keys that way until the owner confirms an
// address.
var ErrNoUserID = errors.New("the answer has no user ID (keys.openpgp.org publishes user IDs only after the owner confirms the address); try --sources hkp, or --email ADDR for WKD")

// Import adds a new key (used by `nymkeys fetch` for a fingerprint the user
// asked for by name). Third-party certifications are dropped as in Merge.
func (g GPG) Import(data []byte) error {
	out, stderr, err := g.run(data, "--status-fd", "1", "--import-options", "self-sigs-only", "--import")
	if strings.Contains(string(out), "IMPORT_OK") {
		for _, line := range strings.Split(string(out), "\n") {
			f := strings.Fields(line)
			if len(f) >= 3 && f[1] == "IMPORT_OK" {
				if flags, _ := strconv.Atoi(f[2]); flags&16 != 0 {
					return errors.New("refusing: the answer contains a secret key")
				}
			}
		}
		return nil
	}
	for _, line := range strings.Split(string(out), "\n") {
		f := strings.Fields(line)
		if len(f) >= 4 && f[1] == "IMPORT_RES" && f[3] != "0" {
			return ErrNoUserID
		}
	}
	if err != nil {
		return fmt.Errorf("gpg --import: %v: %s", err, firstLine(stderr))
	}
	return errors.New("gpg imported nothing")
}

func firstLine(b []byte) string {
	s := strings.TrimSpace(string(b))
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	return s
}
