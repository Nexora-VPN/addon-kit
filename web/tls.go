package web

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

// The install's `https` answers.
const (
	// HTTPSOff serves plain HTTP only; a reverse proxy in front may add TLS.
	HTTPSOff = "off"
	// HTTPSACME gets the public address's certificate from an ACME CA (Let's
	// Encrypt by default) by TLS-ALPN-01, answered on the HTTPS port itself,
	// so nothing listens on 80; the CA asks on 443, whatever port the
	// address names.
	HTTPSACME = "acme"
	// HTTPSSelfSigned makes a certificate of its own for the public
	// address's host — an IP or a domain — for an install without a domain
	// a CA would sign. Browsers warn; the traffic is encrypted, and the
	// fingerprint (TLS.Fingerprint) is what the admin compares.
	HTTPSSelfSigned = "self-signed"
)

// HTTPSModes are the answers an `https` option offers.
var HTTPSModes = []string{HTTPSOff, HTTPSACME, HTTPSSelfSigned}

// selfSignedLife is how long a self-signed certificate is made for: within
// the 398 days browsers and Apple's platforms accept, renewed 30 days before
// it ends.
const selfSignedLife = 397 * 24 * time.Hour

// TLS is how an addon serves its public address over HTTPS.
type TLS struct {
	// Mode is HTTPSACME or HTTPSSelfSigned.
	Mode string
	// Host is the public address's host, asked on every handshake, so a
	// changed address takes effect without a restart. HostOf reads it from
	// an address.
	Host func() string
	// Dir is the addon's data directory: ACME keeps its account and
	// certificates in acme/, a self-signed certificate is kept in tls/.
	Dir string
	// ACMEDirectory and ACMEInsecure point ACME at another CA, such as a
	// test CA whose own certificate nobody trusts.
	ACMEDirectory string
	ACMEInsecure  bool

	once sync.Once
	self *selfSigned
}

// HostOf is an address's host in lower case, "" for one that is not an
// absolute http(s) URL.
func HostOf(address string) string {
	u, err := url.Parse(strings.TrimSpace(address))
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") {
		return ""
	}
	return strings.ToLower(u.Hostname())
}

// Config is the tls.Config that serves the mode's certificate.
func (t *TLS) Config() (*tls.Config, error) {
	if t.Host == nil {
		return nil, errors.New("web: TLS needs the public address's host")
	}
	switch t.Mode {
	case HTTPSACME:
		m := &autocert.Manager{
			Prompt: autocert.AcceptTOS,
			Cache:  autocert.DirCache(filepath.Join(t.Dir, "acme")),
			HostPolicy: func(_ context.Context, host string) error {
				want := t.Host()
				if want == "" || net.ParseIP(want) != nil {
					return errors.New("acme: the public address has no domain for a CA to sign; choose a self-signed certificate for an address by IP")
				}
				if !strings.EqualFold(host, want) {
					return fmt.Errorf("acme: %s is not the public address", host)
				}
				return nil
			},
		}
		if t.ACMEDirectory != "" {
			hc := http.DefaultClient
			if t.ACMEInsecure {
				hc = &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}} //nolint:gosec // a test CA only
			}
			m.Client = &acme.Client{DirectoryURL: t.ACMEDirectory, HTTPClient: hc}
		}
		return m.TLSConfig(), nil
	case HTTPSSelfSigned:
		s := t.selfSigned()
		return &tls.Config{
			MinVersion: tls.VersionTLS12,
			GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
				return s.current(t.Host())
			},
		}, nil
	}
	return nil, fmt.Errorf("web: %q is not an HTTPS mode (%s)", t.Mode, strings.Join(HTTPSModes[1:], ", "))
}

// Serve serves h over TLS on addr until ctx ends.
func (t *TLS) Serve(ctx context.Context, addr string, h http.Handler) error {
	cfg, err := t.Config()
	if err != nil {
		return err
	}
	// An internet-facing listener: a body trickled in, or a connection held
	// idle, is cut off. No write deadline, which would cut a long download
	// (a backup archive) short.
	srv := &http.Server{
		Addr: addr, Handler: h, TLSConfig: cfg,
		ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 2 * time.Minute, IdleTimeout: 2 * time.Minute,
	}
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
	}()
	log.Printf("https on %s for the public address (%s)", addr, t.Mode)
	if err := srv.ListenAndServeTLS("", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// Fingerprint is the SHA-256 of the self-signed certificate served now, as
// colon-separated hex — what an admin compares with the browser's — or ""
// in another mode or before there is one.
func (t *TLS) Fingerprint() string {
	if t.Mode != HTTPSSelfSigned || t.Host == nil {
		return ""
	}
	c, err := t.selfSigned().current(t.Host())
	if err != nil || len(c.Certificate) == 0 {
		return ""
	}
	sum := sha256.Sum256(c.Certificate[0])
	parts := make([]string, len(sum))
	for i, b := range sum {
		parts[i] = fmt.Sprintf("%02X", b)
	}
	return strings.Join(parts, ":")
}

func (t *TLS) selfSigned() *selfSigned {
	t.once.Do(func() { t.self = &selfSigned{dir: filepath.Join(t.Dir, "tls")} })
	return t.self
}

// selfSigned keeps one certificate for the public host on disk, made anew
// when the host changes or the certificate nears its end.
type selfSigned struct {
	dir  string
	mu   sync.Mutex
	cert *tls.Certificate
	leaf *x509.Certificate
}

func (s *selfSigned) current(host string) (*tls.Certificate, error) {
	if host == "" {
		host = "localhost"
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cert == nil {
		s.load()
	}
	if s.cert != nil && s.fits(host) {
		return s.cert, nil
	}
	if err := s.make(host); err != nil {
		return nil, err
	}
	return s.cert, nil
}

// fits is whether the certificate names host and has more than 30 days.
func (s *selfSigned) fits(host string) bool {
	if s.leaf == nil || time.Until(s.leaf.NotAfter) < 30*24*time.Hour {
		return false
	}
	return s.leaf.VerifyHostname(host) == nil
}

func (s *selfSigned) paths() (string, string) {
	return filepath.Join(s.dir, "self-signed.crt"), filepath.Join(s.dir, "self-signed.key")
}

func (s *selfSigned) load() {
	certFile, keyFile := s.paths()
	c, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil || len(c.Certificate) == 0 {
		return
	}
	leaf, err := x509.ParseCertificate(c.Certificate[0])
	if err != nil {
		return
	}
	s.cert, s.leaf = &c, leaf
}

func (s *selfSigned) make(host string) error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: host},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(selfSignedLife),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	if ip := net.ParseIP(host); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = []string{host}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return err
	}
	certFile, keyFile := s.paths()
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		return err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return err
	}
	s.cert = &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
	s.leaf = leaf
	log.Printf("https: a self-signed certificate made for %s, until %s", host, leaf.NotAfter.Format("2006-01-02"))
	return nil
}
