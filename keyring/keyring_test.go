package keyring

import (
	"strings"
	"testing"
)

func TestNormFingerprint(t *testing.T) {
	good := map[string]string{
		"a490 d0f4 d311 a415 3e2b  b7ca dbb8 02b2 58ac d84f": "A490D0F4D311A4153E2BB7CADBB802B258ACD84F",
		"0xEF6E286DDA85EA2A4BA7DE684E2C6E8793298290":         "EF6E286DDA85EA2A4BA7DE684E2C6E8793298290",
	}
	for in, want := range good {
		got, err := NormFingerprint(in)
		if err != nil || got != want {
			t.Errorf("NormFingerprint(%q) = %q, %v", in, got, err)
		}
	}
	// Short and long key ids are collidable; refuse them.
	for _, bad := range []string{"", "DBB802B258ACD84F", "58ACD84F", "0x58ACD84F", "Z490D0F4D311A4153E2BB7CADBB802B258ACD84F", "tails@tails.net"} {
		if _, err := NormFingerprint(bad); err == nil {
			t.Errorf("NormFingerprint(%q) accepted", bad)
		}
	}
}

const colons = `tru::1:1763020800:0:3:1:5
pub:e:255:22:528897B826403ADA:1588330000:1700000000::-:::scESC::::::23::0:
fpr:::::::::6DAA6E64A76D2840571B4902528897B826403ADA:
uid:e::::1588330000::ABCD::Werner Koch (dist signing 2020)::::::::::0:
sig:::22:528897B826403ADA:1588330000::::Werner Koch (dist signing 2020):13x::6DAA6E64A76D2840571B4902528897B826403ADA:::10:
pub:r:255:22:DBB802B258ACD84F:1435000000:::-:::scESC::::::23::0:
fpr:::::::::A490D0F4D311A4153E2BB7CADBB802B258ACD84F:
uid:r::::1435000000::EF01::Tails developers \x3ctails@tails.net\x3e::::::::::0:
uid:r::::1435000000::EF02::Tails list <tails-l@boum.org>::::::::::0:
rev:::22:DBB802B258ACD84F:1700000000::::Tails:20x::A490D0F4D311A4153E2BB7CADBB802B258ACD84F:::10:
sub:r:255:18:AAAAAAAAAAAAAAAA:1435000000::::::e::::::23:
fpr:::::::::0000000000000000000000000000AAAAAAAAAAAAAAAA:
sub:r:255:22:BBBBBBBBBBBBBBBB:1435000000::::::s::::::23:
fpr:::::::::0000000000000000000000000000BBBBBBBBBBBBBBBB:
`

func TestParseColons(t *testing.T) {
	keys := ParseColons([]byte(colons))
	if len(keys) != 2 {
		t.Fatalf("got %d keys", len(keys))
	}
	w, tails := keys[0], keys[1]
	if w.Fingerprint != "6DAA6E64A76D2840571B4902528897B826403ADA" || w.Validity != "e" || w.Expires.Unix() != 1700000000 {
		t.Errorf("werner: %+v", w)
	}
	if len(w.Emails) != 0 || w.Signatures != 1 {
		t.Errorf("werner emails/sigs: %+v", w)
	}
	if tails.Fingerprint != "A490D0F4D311A4153E2BB7CADBB802B258ACD84F" || !tails.Revoked() {
		t.Errorf("tails: %+v", tails)
	}
	if tails.Subkeys != 2 || tails.Signatures != 1 {
		t.Errorf("tails subkeys/sigs: %+v", tails)
	}
	if strings.Join(tails.Emails, ",") != "tails@tails.net,tails-l@boum.org" {
		t.Errorf("emails %v (escaped \\x3c must be decoded)", tails.Emails)
	}
	if tails.Short() != "DBB802B258ACD84F" {
		t.Errorf("short %s", tails.Short())
	}
}

func TestInspectRejectsGarbage(t *testing.T) {
	g := GPG{Home: t.TempDir()}
	if _, err := g.Inspect([]byte("<html>Not Found</html>")); err == nil {
		t.Fatal("garbage accepted")
	}
}
