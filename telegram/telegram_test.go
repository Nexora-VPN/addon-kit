package telegram

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestTheProxyIsTheOperatorsOnly: a socks5h proxy is dialled as socks5, an
// unknown scheme is refused, and with none the environment's proxy is not
// used either.
func TestTheProxyIsTheOperatorsOnly(t *testing.T) {
	c, err := HTTPClient("socks5h://127.0.0.1:1080")
	if err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest(http.MethodGet, "https://api.telegram.org/", nil)
	u, _ := c.Transport.(*http.Transport).Proxy(req)
	if u == nil || u.Scheme != "socks5" || u.Host != "127.0.0.1:1080" {
		t.Fatalf("proxy = %v", u)
	}
	if _, err := HTTPClient("ftp://x:1"); err == nil {
		t.Fatal("an ftp proxy was taken")
	}
	t.Setenv("HTTPS_PROXY", "http://10.0.0.1:3128")
	c, _ = HTTPClient("")
	if c.Transport.(*http.Transport).Proxy != nil {
		t.Fatal("the environment's proxy was used")
	}
	if (Bot{Token: "123:abc"}).ID() != "123" {
		t.Fatal("bot id")
	}
}

// TestAnotherAPIBaseSpeaksTheSameMethods: a message sent through a mirror or
// Bale's address reaches /bot<token>/sendMessage there, as HTML with no link
// preview; a refusal comes back as *Error with the flood wait, and a chat
// that blocked the bot is told apart from a failure worth retrying.
func TestAnotherAPIBaseSpeaksTheSameMethods(t *testing.T) {
	var got map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/bot1:tok/sendMessage":
			_ = json.NewDecoder(r.Body).Decode(&got)
			if got["chat_id"] == float64(42) {
				_, _ = w.Write([]byte(`{"ok":true,"result":{"message_id":7,"chat":{"id":42}}}`))
				return
			}
			if got["chat_id"] == float64(43) {
				_, _ = w.Write([]byte(`{"ok":false,"error_code":403,"description":"Forbidden: bot was blocked by the user"}`))
				return
			}
			_, _ = w.Write([]byte(`{"ok":false,"error_code":429,"description":"Too Many Requests","parameters":{"retry_after":5}}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	b := Bot{Token: "1:tok", APIBase: srv.URL + "/"}
	m, err := b.Send(context.Background(), 42, "<b>hi</b>", nil)
	if err != nil || m.MessageID != 7 {
		t.Fatalf("send: %v %+v", err, m)
	}
	if got["parse_mode"] != "HTML" || got["text"] != "<b>hi</b>" {
		t.Fatalf("sent %v", got)
	}
	_, err = b.Send(context.Background(), 43, "x", nil)
	if !Blocked(err) {
		t.Fatalf("a blocked chat: %v", err)
	}
	_, err = b.Send(context.Background(), 44, "x", nil)
	var e *Error
	if !errors.As(err, &e) || e.RetryAfter != 5 || Blocked(err) {
		t.Fatalf("flood control: %v", err)
	}
}

// TestTheTokenNeverReachesAnError: a transport failure names the address
// without the token in it.
func TestTheTokenNeverReachesAnError(t *testing.T) {
	b := Bot{Token: "9:secret-token", APIBase: "http://127.0.0.1:1"}
	_, err := b.Me(context.Background())
	if err == nil || strings.Contains(err.Error(), "secret-token") {
		t.Fatalf("error = %v", err)
	}
	if (Bot{}).base() != TelegramAPI || BaleAPI != "https://tapi.bale.ai" {
		t.Fatal("the default addresses")
	}
}
