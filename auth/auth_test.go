package auth

import (
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestPasswordsAndTokens(t *testing.T) {
	if _, err := HashPassword("short"); err != ErrShortPassword {
		t.Fatalf("short password: %v", err)
	}
	h, err := HashPassword("long enough password")
	if err != nil || !CheckPassword(h, "long enough password") || CheckPassword(h, "another password") {
		t.Fatalf("hash: %v", err)
	}
	a, b := RandomToken(), RandomToken()
	if len(a) != 64 || a == b || HashToken(a) == a || HashToken(a) != HashToken(a) {
		t.Fatal("tokens")
	}
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "[2001:db8::1]:5555"
	if ClientAddr(r) != "2001:db8::1" {
		t.Fatalf("addr %q", ClientAddr(r))
	}
}

// TestACodeIsTakenOnce: a code is good one step either side, never twice,
// and the enrolment URI names the addon.
func TestACodeIsTakenOnce(t *testing.T) {
	secret, err := NewTOTPSecret()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 0)
	code := TOTPCode(secret, now)
	step, ok := VerifyTOTP(secret, code, now, 0)
	if !ok {
		t.Fatal("the current code was refused")
	}
	if _, ok := VerifyTOTP(secret, code, now, step); ok {
		t.Fatal("the same code was taken twice")
	}
	if _, ok := VerifyTOTP(secret, TOTPCode(secret, now.Add(-30*time.Second)), now, 0); !ok {
		t.Fatal("one step of skew was refused")
	}
	if _, ok := VerifyTOTP(secret, TOTPCode(secret, now.Add(-90*time.Second)), now, 0); ok {
		t.Fatal("three steps back was taken")
	}
	uri := TOTPURI("Nexora Notif", "admin", secret)
	if !strings.HasPrefix(uri, "otpauth://totp/Nexora%20Notif:admin?") || !strings.Contains(uri, "issuer=Nexora+Notif") {
		t.Fatalf("uri %s", uri)
	}
}

func TestTheLimiterForgets(t *testing.T) {
	l := NewLimiter(3, time.Minute)
	at := time.Unix(1000, 0)
	l.now = func() time.Time { return at }
	for range 3 {
		if l.Locked("a") {
			t.Fatal("locked early")
		}
		l.Fail("a")
	}
	if !l.Locked("a") || l.Locked("b") {
		t.Fatal("three failures did not lock, or locked another key")
	}
	at = at.Add(61 * time.Second)
	if l.Locked("a") {
		t.Fatal("the window did not slide")
	}
}
