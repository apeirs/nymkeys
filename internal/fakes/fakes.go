// Package fakes provides offline stand-ins for the mixnet pieces: a SOCKS5
// proxy that records every CONNECT and a throwaway CA.
package fakes

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"fmt"
	"io"
	"math/big"
	"net"
	"sync"
	"time"
)

// SOCKS is a fake nym-socks5-client. Routes maps a requested "host:port"
// (exactly as the client sent it) to a local address to splice to.
type SOCKS struct {
	Addr string

	mu       sync.Mutex
	Requests []Request
	Routes   map[string]string
	ln       net.Listener
}

// Request is one CONNECT the proxy received.
type Request struct {
	ATYP byte // 1 = IPv4, 3 = domain name, 4 = IPv6
	Host string
	Port int
}

func (r Request) String() string { return fmt.Sprintf("%s:%d(atyp %d)", r.Host, r.Port, r.ATYP) }

// NewSOCKS starts the proxy on 127.0.0.1:0.
func NewSOCKS(routes map[string]string) *SOCKS {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	s := &SOCKS{Addr: ln.Addr().String(), Routes: routes, ln: ln}
	go s.serve()
	return s
}

func (s *SOCKS) Close() { s.ln.Close() }

// Seen returns a copy of the CONNECT requests so far.
func (s *SOCKS) Seen() []Request {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Request(nil), s.Requests...)
}

func (s *SOCKS) serve() {
	for {
		c, err := s.ln.Accept()
		if err != nil {
			return
		}
		go s.handle(c)
	}
}

func (s *SOCKS) handle(c net.Conn) {
	defer c.Close()
	buf := make([]byte, 262)
	if _, err := io.ReadFull(c, buf[:3]); err != nil {
		return
	}
	c.Write([]byte{5, 0})
	if _, err := io.ReadFull(c, buf[:4]); err != nil {
		return
	}
	req := Request{ATYP: buf[3]}
	switch req.ATYP {
	case 1:
		io.ReadFull(c, buf[:4])
		req.Host = net.IP(buf[:4]).String()
	case 4:
		io.ReadFull(c, buf[:16])
		req.Host = net.IP(buf[:16]).String()
	case 3:
		io.ReadFull(c, buf[:1])
		n := int(buf[0])
		io.ReadFull(c, buf[:n])
		req.Host = string(buf[:n])
	}
	io.ReadFull(c, buf[:2])
	req.Port = int(binary.BigEndian.Uint16(buf[:2]))
	s.mu.Lock()
	s.Requests = append(s.Requests, req)
	target, ok := s.Routes[net.JoinHostPort(req.Host, fmt.Sprint(req.Port))]
	s.mu.Unlock()
	if !ok {
		c.Write([]byte{5, 4, 0, 1, 0, 0, 0, 0, 0, 0}) // host unreachable
		return
	}
	up, err := net.Dial("tcp", target)
	if err != nil {
		c.Write([]byte{5, 5, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	defer up.Close()
	c.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 0})
	done := make(chan struct{}, 2)
	go func() { io.Copy(up, c); done <- struct{}{} }()
	go func() { io.Copy(c, up); done <- struct{}{} }()
	<-done
}

// CA is a throwaway certificate authority.
type CA struct {
	Pool *x509.CertPool
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func NewCA() *CA {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "fake CA"},
		NotBefore: time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC), NotAfter: time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return &CA{Pool: pool, cert: cert, key: key}
}

// Leaf issues a server certificate for the given DNS names / IPs, valid from
// an hour ago to an hour from now.
func (ca *CA) Leaf(names ...string) tls.Certificate {
	return ca.LeafAt(time.Now().Add(-time.Hour), time.Now().Add(time.Hour), names...)
}

// LeafAt issues a server certificate valid only between notBefore and notAfter.
func (ca *CA) LeafAt(notBefore, notAfter time.Time, names ...string) tls.Certificate {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: names[0]},
		NotBefore: notBefore, NotAfter: notAfter,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, KeyUsage: x509.KeyUsageDigitalSignature,
	}
	for _, n := range names {
		if ip := net.ParseIP(n); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, n)
		}
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// Route adds or replaces a route while the proxy runs.
func (s *SOCKS) Route(hostport, target string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Routes[hostport] = target
}
