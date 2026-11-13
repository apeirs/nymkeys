package wkd

import "testing"

// Vectors from `gpg-wks-client --print-wkd-url` (GnuPG 2.4.9).
func TestURLsMatchGnuPG(t *testing.T) {
	cases := []struct{ addr, adv string }{
		{"Joe.Doe@Example.ORG", "https://openpgpkey.example.org/.well-known/openpgpkey/example.org/hu/iy9q119eutrkn8s1mk4r39qejnbu3n5q?l=joe.doe"},
		{"tails@boum.org", "https://openpgpkey.boum.org/.well-known/openpgpkey/boum.org/hu/qgsj75mkq4temmodm9wrwje7k4zjjbpr?l=tails"},
	}
	for _, c := range cases {
		adv, direct, err := URLs(c.addr)
		if err != nil {
			t.Fatal(err)
		}
		if adv != c.adv {
			t.Errorf("%s: advanced\n got %s\nwant %s", c.addr, adv, c.adv)
		}
		if want := "https://example.org/.well-known/openpgpkey/hu/iy9q119eutrkn8s1mk4r39qejnbu3n5q?l=joe.doe"; c.addr == "Joe.Doe@Example.ORG" && direct != want {
			t.Errorf("direct\n got %s\nwant %s", direct, want)
		}
	}
}

func TestSplitRejects(t *testing.T) {
	for _, a := range []string{"", "nobody", "@x.org", "a@", "a b@x.org", "a@x.org/evil", "a@x.org?y"} {
		if _, _, err := Split(a); err == nil {
			t.Errorf("Split(%q) accepted", a)
		}
	}
}

func TestZBase32(t *testing.T) {
	// RFC 6189 / zbase32 reference: 0xF0 0xBF 0xC7 -> "6n9hq"
	if got := ZBase32([]byte{0xF0, 0xBF, 0xC7}); got != "6n9hq" {
		t.Errorf("got %q", got)
	}
}
