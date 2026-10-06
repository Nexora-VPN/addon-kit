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
	// HTTPSPanel serves the certificate the panel holds for the addon,
	// fetched from it (TLS.Panel) and kept in <Dir>/tls-panel so a restart
	// while the panel is down still serves it. The panel issues and renews
	// it; the addon needs no ACME and no port 443 of its own, so several
	// addons share one host, the panel's included.
	HTTPSPanel = "panel"
	// HTTPSACME gets the public address's certificate from an ACME CA (Let's
	// Encrypt by default) by TLS-ALPN-01, answered on the HTTPS port itself,
	// so nothing listens on 80; the CA asks on 443, so the addon serves on
	// 443.
	HTTPSACME = "acme"
	// HTTPSACMEHTTP is HTTPSACME answering the CA's HTTP-01 check on port 80
	// (TLS.HTTPListen) as well, for a host whose 443 something else holds;
	// for an addon on a server of its own, never beside the panel.
	HTTPSACMEHTTP = "acme-http"
	// HTTPSSelfSigned makes a certificate of its own for the public
	// address's host — an IP or a domain — for an install without a domain
	// a CA would sign. Browsers warn; the traffic is encrypted, and the
	// fingerprint (TLS.Fingerprint) is what the admin compares — with the
	// one the panel shows when it is asked to trust the certificate.
	HTTPSSelfSigned = "self-signed"
)

// HTTPSModes are the answers an `https` option offers.
var HTTPSModes = []string{HTTPSOff, HTTPSPanel, HTTPSACME, HTTPSACMEHTTP, HTTPSSelfSigned}

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
	// HTTPListen is where HTTPSACMEHTTP answers the CA's HTTP-01 check;
	// empty is ":80".
	HTTPListen string
	// Panel is where an HTTPSPanel certificate comes from: the addon's link
	// to its panel (*addon.Addon is one). Required in that mode.
	Panel CertSource
	// PanelRefresh is how often the panel is asked for a newer certificate
	// once one is held; zero is every five minutes. An unchanged one costs
	// a 304.
	PanelRefresh time.Duration

	once    sync.Once
	self    *selfSigned
	panel   *panelCert
	manager *autocert.Manager
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
	case HTTPSPanel:
		if t.Panel == nil {
			return nil, errors.New("web: https panel needs the addon's link to its panel (TLS.Panel)")
		}
		p := t.panelCert()
		return &tls.Config{
			MinVersion:     tls.VersionTLS12,
			GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return p.current() },
		}, nil
	case HTTPSACME, HTTPSACMEHTTP:
		m := &autocert.Manager{
			Prompt: autocert.AcceptTOS,
			Cache:  autocert.DirCache(filepath.Join(t.Dir, "acme")),
			HostPolicy: func(_ context.Context, host string) error {
				// The HTTP-01 check asks with a Host header, which names
				// the port when it is not 80.
				if h, _, err := net.SplitHostPort(host); err == nil {
					host = h
				}
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
		t.manager = m
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

// Serve serves h over TLS on addr until ctx ends, then lets the requests
// in hand finish, for up to 10 seconds, before it returns.
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
	shutDown := make(chan struct{})
	go func() {
		defer close(shutDown)
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
	}()
	switch t.Mode {
	case HTTPSPanel:
		go t.panelCert().run(ctx, t.PanelRefresh)
	case HTTPSACMEHTTP:
		if err := t.serveHTTP01(ctx, addr); err != nil {
			return err
		}
	}
	log.Printf("https on %s for the public address (%s)", addr, t.Mode)
	if err := srv.ListenAndServeTLS("", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	// ListenAndServeTLS returns as Shutdown begins; the requests in hand
	// end when it does.
	<-shutDown
	return nil
}

// serveHTTP01 answers the CA's HTTP-01 check on HTTPListen, and sends any
// other request there to https on httpsAddr's port — the addon's own, not
// 443, which acme-http leaves to whatever holds it.
func (t *TLS) serveHTTP01(ctx context.Context, httpsAddr string) error {
	addr := t.HTTPListen
	if addr == "" {
		addr = ":80"
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("the CA's HTTP-01 check needs %s: %w", addr, err)
	}
	srv := &http.Server{Handler: t.manager.HTTPHandler(httpsRedirect(httpsAddr)), ReadHeaderTimeout: 10 * time.Second}
	go func() {
		<-ctx.Done()
		_ = srv.Close()
	}()
	go func() { _ = srv.Serve(ln) }()
	log.Printf("http on %s for the CA's HTTP-01 check", addr)
	return nil
}

// SelfSigned is whether the certificate served is one no public CA vouches
// for — the self-signed mode, or a self-signed certificate from the panel —
// so a check of the public address can look only at what answers, and a
// browser warns.
func (t *TLS) SelfSigned() bool {
	switch t.Mode {
	case HTTPSSelfSigned:
		return true
	case HTTPSPanel:
		c, err := t.panelCert().current()
		if err != nil || c.Leaf == nil {
			return false
		}
		host := ""
		if t.Host != nil {
			host = t.Host()
		}
		return !vouched(c, host, nil)
	}
	return false
}

// vouched is whether a CA in roots (nil: the system's) vouches for c's leaf
// at host, through the chain c carries — a public CA signs through an
// intermediate, and Go fetches none that is missing.
func vouched(c *tls.Certificate, host string, roots *x509.CertPool) bool {
	if c.Leaf == nil || len(c.Certificate) == 0 {
		return false
	}
	inter := x509.NewCertPool()
	for _, der := range c.Certificate[1:] {
		if ic, err := x509.ParseCertificate(der); err == nil {
			inter.AddCert(ic)
		}
	}
	_, err := c.Leaf.Verify(x509.VerifyOptions{DNSName: host, Intermediates: inter, Roots: roots})
	return err == nil
}

// Fingerprint is the SHA-256 of the self-signed certificate served now —
// its own, or one from the panel — as colon-separated hex, what an admin
// compares with the browser's; "" for a certificate a CA vouches for, or
// before there is one.
func (t *TLS) Fingerprint() string {
	var c *tls.Certificate
	var err error
	switch {
	case t.Mode == HTTPSSelfSigned && t.Host != nil:
		c, err = t.selfSigned().current(t.Host())
	case t.Mode == HTTPSPanel && t.SelfSigned():
		c, err = t.panelCert().current()
	default:
		return ""
	}
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
	t.once.Do(t.init)
	return t.self
}

func (t *TLS) panelCert() *panelCert {
	t.once.Do(t.init)
	return t.panel
}

func (t *TLS) init() {
	t.self = &selfSigned{dir: filepath.Join(t.Dir, "tls")}
	t.panel = &panelCert{src: t.Panel, dir: filepath.Join(t.Dir, "tls-panel")}
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

// httpsRedirect sends a plain request to the same host and path over https
// on httpsAddr's port; none, or 443, is https's own.
func httpsRedirect(httpsAddr string) http.Handler {
	_, port, _ := net.SplitHostPort(httpsAddr)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.Error(w, "use https", http.StatusBadRequest)
			return
		}
		host := r.Host
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		host = strings.Trim(host, "[]")
		if strings.Contains(host, ":") {
			host = "[" + host + "]"
		}
		if port != "" && port != "443" {
			host += ":" + port
		}
		http.Redirect(w, r, "https://"+host+r.URL.RequestURI(), http.StatusFound)
	})
}
