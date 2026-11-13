package source

import (
	"context"
	"strings"
	"testing"

	"github.com/apeirs/nymkeys/keyring"
)

func TestParse(t *testing.T) {
	s, err := Parse("vks, WKD,vks,hkp", "", "")
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, x := range s {
		names = append(names, x.Name())
	}
	if strings.Join(names, ",") != "vks,wkd,hkp" {
		t.Errorf("got %v", names)
	}
	for _, bad := range []string{"", "ldap", "vks,finger"} {
		if _, err := Parse(bad, "", ""); err == nil {
			t.Errorf("Parse(%q) accepted", bad)
		}
	}
}

func TestPlainHTTPKeyserverRefused(t *testing.T) {
	// No client needed: the URL is refused before anything is dialed.
	_, err := VKS{Base: "http://keys.openpgp.org"}.Fetch(context.Background(), nil, keyring.Key{Fingerprint: "A490D0F4D311A4153E2BB7CADBB802B258ACD84F"}, 0)
	if err == nil || !strings.Contains(err.Error(), "not https") {
		t.Fatalf("err = %v", err)
	}
	_, err = HKP{Base: "hkp://keyserver.ubuntu.com"}.Fetch(context.Background(), nil, keyring.Key{Fingerprint: "A490D0F4D311A4153E2BB7CADBB802B258ACD84F"}, 0)
	if err == nil || !strings.Contains(err.Error(), "not https") {
		t.Fatalf("err = %v", err)
	}
}

func TestWKDWithoutEmailIsSkipped(t *testing.T) {
	_, err := WKD{}.Fetch(context.Background(), nil, keyring.Key{Fingerprint: "A490D0F4D311A4153E2BB7CADBB802B258ACD84F"}, 0)
	if err != ErrSkipped {
		t.Fatalf("err = %v", err)
	}
}
