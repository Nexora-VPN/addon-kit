package web

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// CertSource hands out the certificate the panel holds for the addon
// (HTTPSPanel): *addon.Addon is one. have is the hex SHA-256 of the leaf
// held now, "" for none; a certificate still the same comes back as nil PEM
// and no error.
type CertSource interface {
	PanelCertificate(ctx context.Context, have string) (certPEM, keyPEM []byte, err error)
}

// panelCert is the certificate from the panel: the copy on disk, then
// whatever the panel hands out, asked again on a schedule.
type panelCert struct {
	src CertSource
	dir string

	mu     sync.RWMutex
	cert   *tls.Certificate
	sum    string
	loaded bool
}

func (p *panelCert) paths() (string, string) {
	return filepath.Join(p.dir, "cert.pem"), filepath.Join(p.dir, "key.pem")
}

// current is the certificate to serve: the one held, or the copy on disk the
// first time.
func (p *panelCert) current() (*tls.Certificate, error) {
	p.mu.RLock()
	c, loaded := p.cert, p.loaded
	p.mu.RUnlock()
	if !loaded {
		p.load()
		p.mu.RLock()
		c = p.cert
		p.mu.RUnlock()
	}
	if c == nil {
		return nil, errors.New("no certificate from the panel yet")
	}
	return c, nil
}

func (p *panelCert) load() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.loaded {
		return
	}
	p.loaded = true
	certFile, keyFile := p.paths()
	certPEM, err1 := os.ReadFile(certFile)
	keyPEM, err2 := os.ReadFile(keyFile)
	if err1 != nil || err2 != nil {
		return
	}
	if c, sum, err := parsePair(certPEM, keyPEM); err == nil {
		p.cert, p.sum = c, sum
	}
}

// refresh asks the panel once and keeps a newer certificate, on disk too.
func (p *panelCert) refresh(ctx context.Context) error {
	if p.src == nil {
		return errors.New("no link to the panel")
	}
	_, _ = p.current() // the copy on disk, the first time
	p.mu.RLock()
	have := p.sum
	p.mu.RUnlock()
	certPEM, keyPEM, err := p.src.PanelCertificate(ctx, have)
	if err != nil {
		return err
	}
	if certPEM == nil {
		return nil
	}
	c, sum, err := parsePair(certPEM, keyPEM)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(p.dir, 0o700); err != nil {
		return err
	}
	certFile, keyFile := p.paths()
	if err := writeAtomic(keyFile, keyPEM, 0o600); err != nil {
		return err
	}
	if err := writeAtomic(certFile, certPEM, 0o644); err != nil {
		return err
	}
	p.mu.Lock()
	p.cert, p.sum, p.loaded = c, sum, true
	p.mu.Unlock()
	names := append([]string{}, c.Leaf.DNSNames...)
	for _, ip := range c.Leaf.IPAddresses {
		names = append(names, ip.String())
	}
	log.Printf("https: the panel's certificate for %s, until %s", strings.Join(names, ", "), c.Leaf.NotAfter.Format("2006-01-02"))
	return nil
}

// run asks the panel now, then every interval while a certificate is held
// and every half minute while none is, until ctx ends.
func (p *panelCert) run(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = 5 * time.Minute
	}
	for {
		wait := interval
		if err := p.refresh(ctx); err != nil {
			log.Printf("https: the certificate from the panel: %v", err)
			if _, err := p.current(); err != nil {
				wait = 30 * time.Second
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
	}
}

func parsePair(certPEM, keyPEM []byte) (*tls.Certificate, string, error) {
	c, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, "", err
	}
	leaf, err := x509.ParseCertificate(c.Certificate[0])
	if err != nil {
		return nil, "", err
	}
	c.Leaf = leaf
	sum := sha256.Sum256(c.Certificate[0])
	return &c, hex.EncodeToString(sum[:]), nil
}

func writeAtomic(path string, data []byte, mode os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, mode); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
