package web

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestAPlainRequestGoesToTheAddonsOwnHTTPSPort: acme-http leaves 443 to
// whatever holds it, so http is sent to the addon's port.
func TestAPlainRequestGoesToTheAddonsOwnHTTPSPort(t *testing.T) {
	for _, c := range []struct{ addr, host, want string }{
		{":8095", "shop.example.com", "https://shop.example.com:8095/a?b=1"},
		{":8095", "shop.example.com:80", "https://shop.example.com:8095/a?b=1"},
		{":443", "shop.example.com", "https://shop.example.com/a?b=1"},
		{":8095", "[2001:db8::1]:80", "https://[2001:db8::1]:8095/a?b=1"},
		{":8095", "[2001:db8::1]", "https://[2001:db8::1]:8095/a?b=1"},
	} {
		req := httptest.NewRequest(http.MethodGet, "http://"+c.host+"/a?b=1", nil)
		req.Host = c.host
		rec := httptest.NewRecorder()
		httpsRedirect(c.addr).ServeHTTP(rec, req)
		if rec.Code != http.StatusFound || rec.Header().Get("Location") != c.want {
			t.Errorf("%s at %s: %d %q, want %q", c.host, c.addr, rec.Code, rec.Header().Get("Location"), c.want)
		}
	}
}
