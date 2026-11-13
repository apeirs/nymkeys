// Package wkd builds Web Key Directory URLs (draft-koch-openpgp-webkey-service).
package wkd

import (
	"crypto/sha1"
	"fmt"
	"net/url"
	"strings"
)

const zbase32Alphabet = "ybndrfg8ejkmcpqxot1uwisza345h769"

// ZBase32 encodes b in z-base-32 (RFC 6189 alphabet), as WKD uses it.
func ZBase32(b []byte) string {
	var out strings.Builder
	var acc uint32
	bits := 0
	for _, c := range b {
		acc = acc<<8 | uint32(c)
		bits += 8
		for bits >= 5 {
			bits -= 5
			out.WriteByte(zbase32Alphabet[(acc>>uint(bits))&31])
		}
	}
	if bits > 0 {
		out.WriteByte(zbase32Alphabet[(acc<<uint(5-bits))&31])
	}
	return out.String()
}

// Split lowercases an address and returns its local part and domain.
func Split(addr string) (local, domain string, err error) {
	addr = strings.ToLower(strings.TrimSpace(addr))
	i := strings.LastIndexByte(addr, '@')
	if i <= 0 || i == len(addr)-1 || strings.ContainsAny(addr, " <>/\\?#") {
		return "", "", fmt.Errorf("%q is not an email address", addr)
	}
	return addr[:i], addr[i+1:], nil
}

// Hash is the z-base-32 SHA-1 of the lowercased local part.
func Hash(local string) string {
	h := sha1.Sum([]byte(strings.ToLower(local)))
	return ZBase32(h[:])
}

// URLs returns the advanced-method URL and the direct-method URL for addr,
// in the order a client should try them.
func URLs(addr string) (advanced, direct string, err error) {
	local, domain, err := Split(addr)
	if err != nil {
		return "", "", err
	}
	h, l := Hash(local), url.QueryEscape(local)
	advanced = fmt.Sprintf("https://openpgpkey.%s/.well-known/openpgpkey/%s/hu/%s?l=%s", domain, domain, h, l)
	direct = fmt.Sprintf("https://%s/.well-known/openpgpkey/hu/%s?l=%s", domain, h, l)
	return advanced, direct, nil
}
