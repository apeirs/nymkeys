package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/apeirs/nymkeys/keyring"
)

var bin string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "nymkeys-cli-")
	if err != nil {
		panic(err)
	}
	bin = filepath.Join(dir, "nymkeys")
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		panic(string(out))
	}
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

func run(t *testing.T, env []string, args ...string) (string, int) {
	t.Helper()
	cmd := exec.Command(bin, args...)
	cmd.Env = append([]string{"PATH=/usr/bin:/bin", "HOME=" + t.TempDir()}, env...)
	out, err := cmd.CombinedOutput()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	}
	return string(out), code
}

// Without a running Nym client (--proxy) or the Nym binary there is no way
// out, and nymkeys must say so rather than fall back to a direct connection.
func TestRefusesWithoutMixnet(t *testing.T) {
	home := t.TempDir()
	os.Chmod(home, 0o700)
	for _, args := range [][]string{
		{"refresh", "--homedir", home, "--now"},
		{"fetch", "--homedir", home, "A490D0F4D311A4153E2BB7CADBB802B258ACD84F"},
		{"daemon", "--homedir", home},
	} {
		out, code := run(t, nil, args...)
		if code == 0 || !strings.Contains(out, "nym-socks5-client not found") {
			t.Errorf("%v: exit %d, output %q", args, code, out)
		}
	}
}

func TestFetchRefusesKeyIDs(t *testing.T) {
	out, code := run(t, nil, "fetch", "--proxy", "127.0.0.1:9", "58ACD84F")
	if code == 0 || !strings.Contains(out, "not a full fingerprint") {
		t.Errorf("exit %d, %q", code, out)
	}
}

func TestWKDURL(t *testing.T) {
	out, code := run(t, nil, "wkd-url", "Joe.Doe@Example.ORG")
	want := "https://openpgpkey.example.org/.well-known/openpgpkey/example.org/hu/iy9q119eutrkn8s1mk4r39qejnbu3n5q?l=joe.doe\n" +
		"https://example.org/.well-known/openpgpkey/hu/iy9q119eutrkn8s1mk4r39qejnbu3n5q?l=joe.doe\n"
	if code != 0 || out != want {
		t.Errorf("exit %d:\n%s", code, out)
	}
}

func TestSelectKeys(t *testing.T) {
	keys := []keyring.Key{
		{Fingerprint: "A490D0F4D311A4153E2BB7CADBB802B258ACD84F"},
		{Fingerprint: "EF6E286DDA85EA2A4BA7DE684E2C6E8793298290", Validity: "r"},
	}
	all, _ := selectKeys(keys, nil, false)
	if len(all) != 1 {
		t.Errorf("revoked key not skipped: %d", len(all))
	}
	all, _ = selectKeys(keys, nil, true)
	if len(all) != 2 {
		t.Errorf("--include-revoked: %d", len(all))
	}
	one, err := selectKeys(keys, []string{"ef6e 286d da85 ea2a 4ba7  de68 4e2c 6e87 9329 8290"}, false)
	if err != nil || len(one) != 1 {
		t.Errorf("by fingerprint: %v %v", one, err)
	}
	if _, err := selectKeys(keys, []string{"6DAA6E64A76D2840571B4902528897B826403ADA"}, false); err == nil {
		t.Error("unknown key accepted")
	}
}
