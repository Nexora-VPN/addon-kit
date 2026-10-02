package addon_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/nexora-vpn/addon-kit/addon"
	"github.com/nexora-vpn/addon-kit/manifest"
)

const testManifest = `{"api": 1, "slug": "demo", "name": "Demo", "version": "0.1.0", "publisher": "x",
  "scopes": [{"scope": "users:read", "purpose": "list"}], "events": ["user.created"],
  "webhook": "/nexora/events", "setup": "/nexora/setup", "health": "/health"}`

func start(t *testing.T, dir string, healthy func() error) (*addon.Addon, *httptest.Server) {
	t.Helper()
	a, err := addon.New(addon.Config{Manifest: []byte(testManifest), ClaimCode: "CODE-1", DataDir: dir, Healthy: healthy, Logf: t.Logf})
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	a.Mount(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return a, srv
}

func post(t *testing.T, url string, body any, header map[string]string) int {
	t.Helper()
	raw, _ := json.Marshal(body)
	req, _ := http.NewRequest(http.MethodPost, url, bytes.NewReader(raw))
	for k, v := range header {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

func setupBody(code string) manifest.SetupRequest {
	return manifest.SetupRequest{
		API: 1, ClaimCode: code, Panel: manifest.SetupPanel{URL: "https://panel.example", Version: "0.1.0"},
		Token: "tok", Scopes: []string{"users:read"},
		Webhook: &manifest.SetupWebhook{ID: 7, URL: "https://addon/nexora/events", Events: []string{"user.created"}, Secret: "s3cret"},
	}
}

func TestTheCredentialsArriveOnceWithTheClaimCodeAndSurviveARestart(t *testing.T) {
	dir := t.TempDir()
	a, srv := start(t, dir, nil)
	if code := post(t, srv.URL+"/nexora/setup", setupBody("WRONG"), nil); code != http.StatusForbidden {
		t.Fatalf("wrong code = %d", code)
	}
	if a.Credentials() != nil {
		t.Fatal("a wrong code delivered credentials")
	}
	if code := post(t, srv.URL+"/nexora/setup", setupBody("CODE-1"), nil); code != http.StatusNoContent {
		t.Fatalf("right code = %d", code)
	}
	if code := post(t, srv.URL+"/nexora/setup", setupBody("CODE-1"), nil); code != http.StatusConflict {
		t.Fatalf("second setup = %d", code)
	}
	again, err := addon.New(addon.Config{Manifest: []byte(testManifest), DataDir: dir, Logf: t.Logf})
	if err != nil {
		t.Fatal(err)
	}
	if c := again.Credentials(); c == nil || c.Token != "tok" || c.Webhook.Secret != "s3cret" || again.ClaimCode() != "" {
		t.Fatalf("after a restart: %+v", c)
	}
}

func TestOnlySignedFreshDeliveriesReachTheAddonOnce(t *testing.T) {
	a, srv := start(t, "", nil)
	post(t, srv.URL+"/nexora/setup", setupBody("CODE-1"), nil)
	var got []addon.Event
	a.OnEvent(func(e addon.Event) { got = append(got, e) })

	body := []byte(`{"v":1,"id":3,"event":"user.created","time":1,"data":{"userId":1}}`)
	send := func(secret string, at time.Time, delivery string) int {
		req, _ := http.NewRequest(http.MethodPost, srv.URL+"/nexora/events", bytes.NewReader(body))
		req.Header.Set("X-Nexora-Signature", addon.Sign(secret, at.Unix(), body))
		req.Header.Set("X-Nexora-Delivery", delivery)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	if code := send("other", time.Now(), "1"); code != http.StatusUnauthorized {
		t.Fatalf("wrong secret = %d", code)
	}
	if code := send("s3cret", time.Now().Add(-10*time.Minute), "1"); code != http.StatusUnauthorized {
		t.Fatalf("stale = %d", code)
	}
	for range 2 {
		if code := send("s3cret", time.Now(), "9"); code != http.StatusNoContent {
			t.Fatalf("good = %d", code)
		}
	}
	if len(got) != 1 || got[0].Event != "user.created" || got[0].ID != 3 || got[0].Delivery != "9" {
		t.Fatalf("handed on %+v, want one user.created", got)
	}
}

func TestHealthAnswersWhatTheAddonSays(t *testing.T) {
	var broken error
	_, srv := start(t, "", func() error { return broken })
	for _, c := range []struct {
		err  error
		want int
	}{{nil, http.StatusOK}, {errors.New("db down"), http.StatusServiceUnavailable}} {
		broken = c.err
		resp, err := http.Get(srv.URL + "/health")
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != c.want {
			t.Fatalf("health with %v = %d, want %d", c.err, resp.StatusCode, c.want)
		}
	}
	resp, _ := http.Get(srv.URL + manifest.WellKnownPath)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("manifest = %d", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestOptionsComeFromTheEnvironment(t *testing.T) {
	t.Setenv("NEXORA_OPT_DATABASE", "postgres")
	t.Setenv("NEXORA_CLAIM_CODE", "FROM-ENV")
	if got := addon.Option("database"); got != "postgres" {
		t.Fatalf("Option = %q", got)
	}
	a, err := addon.New(addon.Config{Manifest: []byte(testManifest), Logf: t.Logf}.FromEnv())
	if err != nil {
		t.Fatal(err)
	}
	if a.ClaimCode() != "FROM-ENV" {
		t.Fatalf("claim code = %q", a.ClaimCode())
	}
}
