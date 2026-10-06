package web

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"testing"
	"time"
)

type fakeSource struct {
	cert, key []byte
	asked     []string
	err       error
}

func (f *fakeSource) PanelCertificate(_ context.Context, have string) ([]byte, []byte, error) {
	f.asked = append(f.asked, have)
	if f.err != nil {
		return nil, nil, f.err
	}
	if _, sum, err := parsePair(f.cert, f.key); err == nil && sum == have {
		return nil, nil, nil
	}
	return f.cert, f.key, nil
}

func selfSignedPEM(t *testing.T, host string) ([]byte, []byte) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: host},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), DNSNames: []string{host},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	kd, _ := x509.MarshalECPrivateKey(key)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kd})
}

// TestThePanelsCertificateIsServedKeptAndRefreshed: nothing is served until
// the panel hands one out; then it is, and kept on disk, so an addon started
// again while the panel is down still serves it; an unchanged one is asked
// for by its hash and not written again; a newer one replaces it.
func TestThePanelsCertificateIsServedKeptAndRefreshed(t *testing.T) {
	dir := t.TempDir()
	certPEM, keyPEM := selfSignedPEM(t, "shop.example.com")
	src := &fakeSource{cert: certPEM, key: keyPEM}
	tl := &TLS{Mode: HTTPSPanel, Host: func() string { return "shop.example.com" }, Dir: dir, Panel: src}
	cfg, err := tl.Config()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cfg.GetCertificate(&tls.ClientHelloInfo{}); err == nil {
		t.Fatal("a certificate was served before the panel handed one out")
	}
	if err := tl.panelCert().refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	got, err := cfg.GetCertificate(&tls.ClientHelloInfo{})
	if err != nil || got.Leaf.DNSNames[0] != "shop.example.com" {
		t.Fatalf("served = %v %v", got, err)
	}
	if !tl.SelfSigned() || tl.Fingerprint() == "" {
		t.Fatalf("a self-signed certificate from the panel: selfSigned %v, fingerprint %q", tl.SelfSigned(), tl.Fingerprint())
	}
	// Unchanged: asked by its hash.
	if err := tl.panelCert().refresh(context.Background()); err != nil || src.asked[1] == "" {
		t.Fatalf("second ask = %v, asked %q", err, src.asked)
	}

	// Started again with the panel down: the copy on disk.
	down := &fakeSource{err: errors.New("panel down")}
	again := &TLS{Mode: HTTPSPanel, Host: func() string { return "shop.example.com" }, Dir: dir, Panel: down}
	cfg2, _ := again.Config()
	if err := again.panelCert().refresh(context.Background()); err == nil {
		t.Fatal("a panel that is down answered")
	}
	if c, err := cfg2.GetCertificate(&tls.ClientHelloInfo{}); err != nil || c.Leaf.DNSNames[0] != "shop.example.com" {
		t.Fatalf("after a restart with the panel down = %v %v", c, err)
	}

	// Renewed in the panel: the next ask replaces it.
	src.cert, src.key = selfSignedPEM(t, "new.example.com")
	if err := tl.panelCert().refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if c, _ := cfg.GetCertificate(&tls.ClientHelloInfo{}); c.Leaf.DNSNames[0] != "new.example.com" {
		t.Fatalf("after a renewal = %v", c.Leaf.DNSNames)
	}
}

func TestPanelModeNeedsTheLinkToThePanel(t *testing.T) {
	if _, err := (&TLS{Mode: HTTPSPanel, Host: func() string { return "x" }, Dir: t.TempDir()}).Config(); err == nil {
		t.Fatal("panel mode without a source")
	}
}

// TestTheHTTP01CheckMayNameAPort: the CA's HTTP-01 check names the port in
// its Host header when it is not 80; the host is still the public one (found
// walking acme-http against a test CA on another port).
func TestTheHTTP01CheckMayNameAPort(t *testing.T) {
	tl := &TLS{Mode: HTTPSACMEHTTP, Host: func() string { return "shop.example.com" }, Dir: t.TempDir()}
	if _, err := tl.Config(); err != nil {
		t.Fatal(err)
	}
	for host, ok := range map[string]bool{"shop.example.com": true, "shop.example.com:18580": true, "other.example.com:80": false} {
		if err := tl.manager.HostPolicy(context.Background(), host); (err == nil) != ok {
			t.Errorf("%s: %v", host, err)
		}
	}
}
