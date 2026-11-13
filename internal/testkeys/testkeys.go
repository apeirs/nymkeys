// Package testkeys makes throwaway OpenPGP keys with the real gpg, and the
// versions of them a keyserver could serve: older, newer, revoked, certified
// by a stranger. Everything lives in a temporary directory.
package testkeys

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Set is one batch of fixtures.
type Set struct {
	Dir string // remove with Cleanup

	Alice, Bob, Carol, Mallory string // fingerprints

	AliceOld       []byte // 1 subkey, expires in 1 year
	AliceNew       []byte // + a second subkey, expires in 3 years
	AliceCertified []byte // AliceNew + a certification by Mallory
	BobKey         []byte
	CarolOld       []byte
	CarolRevoked   []byte
	AliceSecret    []byte // a secret key export, which must never be accepted
}

func run(home string, stdin []byte, args ...string) ([]byte, error) {
	a := append([]string{"--homedir", home, "--batch", "--no-tty", "--yes", "--passphrase", "", "--pinentry-mode", "loopback"}, args...)
	cmd := exec.Command("gpg", a...)
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("gpg %s: %v: %s", strings.Join(args, " "), err, errb.String())
	}
	return out.Bytes(), nil
}

// NewHome makes an empty 0700 GnuPG home under dir.
func NewHome(dir, name string) (string, error) {
	h := filepath.Join(dir, name)
	return h, os.MkdirAll(h, 0o700)
}

func gen(home, uid string) (string, error) {
	if _, err := run(home, nil, "--quick-gen-key", uid, "ed25519", "sign", "1y"); err != nil {
		return "", err
	}
	out, err := run(home, nil, "--with-colons", "--list-keys", uid)
	if err != nil {
		return "", err
	}
	for _, l := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(l, "fpr:") {
			return strings.Split(l, ":")[9], nil
		}
	}
	return "", fmt.Errorf("no fingerprint for %s", uid)
}

// Make builds a Set. It needs gpg (and starts a gpg-agent in the temporary
// home, stopped by Cleanup).
func Make() (*Set, error) {
	if _, err := exec.LookPath("gpg"); err != nil {
		return nil, err
	}
	dir, err := os.MkdirTemp("", "nymkeys-test-")
	if err != nil {
		return nil, err
	}
	s := &Set{Dir: dir}
	home, err := NewHome(dir, "owner")
	if err != nil {
		return s, err
	}
	if s.Alice, err = gen(home, "Alice <alice@example.org>"); err != nil {
		return s, err
	}
	if s.Bob, err = gen(home, "Bob <bob@example.net>"); err != nil {
		return s, err
	}
	if s.Carol, err = gen(home, "Carol <carol@example.org>"); err != nil {
		return s, err
	}
	if s.Mallory, err = gen(home, "Mallory <mallory@example.com>"); err != nil {
		return s, err
	}
	if _, err = run(home, nil, "--quick-add-key", s.Alice, "cv25519", "encr", "1y"); err != nil {
		return s, err
	}
	if s.AliceOld, err = run(home, nil, "--export", s.Alice); err != nil {
		return s, err
	}
	if s.BobKey, err = run(home, nil, "--export", s.Bob); err != nil {
		return s, err
	}
	if s.CarolOld, err = run(home, nil, "--export", s.Carol); err != nil {
		return s, err
	}
	if s.AliceSecret, err = run(home, nil, "--export-secret-keys", s.Alice); err != nil {
		return s, err
	}
	// Alice extends her key and adds a subkey.
	if _, err = run(home, nil, "--quick-set-expire", s.Alice, "3y"); err != nil {
		return s, err
	}
	if _, err = run(home, nil, "--quick-add-key", s.Alice, "ed25519", "sign", "3y"); err != nil {
		return s, err
	}
	if s.AliceNew, err = run(home, nil, "--export", s.Alice); err != nil {
		return s, err
	}
	// Mallory certifies Alice's key (third-party signature).
	if _, err = run(home, nil, "-u", s.Mallory, "--quick-sign-key", s.Alice); err != nil {
		return s, err
	}
	if s.AliceCertified, err = run(home, nil, "--export", s.Alice); err != nil {
		return s, err
	}
	// Carol revokes her key with the certificate gpg made at key generation.
	rev, err := os.ReadFile(filepath.Join(home, "openpgp-revocs.d", s.Carol+".rev"))
	if err != nil {
		return s, err
	}
	rev = bytes.Replace(rev, []byte(":-----BEGIN"), []byte("-----BEGIN"), 1)
	if _, err = run(home, rev, "--import"); err != nil {
		return s, err
	}
	if s.CarolRevoked, err = run(home, nil, "--export", s.Carol); err != nil {
		return s, err
	}
	return s, nil
}

// Cleanup stops the agent and removes everything.
func (s *Set) Cleanup() {
	if s == nil || s.Dir == "" {
		return
	}
	_ = exec.Command("gpgconf", "--homedir", filepath.Join(s.Dir, "owner"), "--kill", "all").Run()
	_ = os.RemoveAll(s.Dir)
}

// Import loads key material into home (a "local keyring" for a test).
func Import(home string, data ...[]byte) error {
	for _, d := range data {
		if _, err := run(home, d, "--import"); err != nil {
			return err
		}
	}
	return nil
}
