// Package auth is what an addon's own admin sign-in is made of: bcrypt
// passwords, session tokens kept only as hashes, a TOTP second factor that
// authenticator apps treat as the panel's, and a limiter for failed
// attempts. Where accounts and sessions are stored is the addon's: this
// package holds no state but the limiter's.
package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net"
	"net/http"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// MinPassword is the shortest password HashPassword takes.
const MinPassword = 10

// ErrShortPassword is a password under MinPassword characters.
var ErrShortPassword = errors.New("a password is at least 10 characters")

// HashPassword is bcrypt at its default cost.
func HashPassword(p string) (string, error) {
	if len(p) < MinPassword {
		return "", ErrShortPassword
	}
	h, err := bcrypt.GenerateFromPassword([]byte(p), bcrypt.DefaultCost)
	return string(h), err
}

// CheckPassword compares a password with a hash.
func CheckPassword(hash, p string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(p)) == nil
}

// RandomToken is 32 random bytes, hex: a session or a one-time link.
func RandomToken() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// HashToken is what a store keeps of a token, so a copy of the database
// signs nobody in.
func HashToken(t string) string {
	sum := sha256.Sum256([]byte(t))
	return hex.EncodeToString(sum[:])
}

// ClientAddr is the request's peer address without the port. It is the
// connection's, never a forwarded header's: an addon behind a proxy it
// trusts sets r.RemoteAddr itself.
func ClientAddr(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// Limiter counts failures per key (a client address, say) in a sliding
// window. The zero value is not usable; make one with NewLimiter.
type Limiter struct {
	max    int
	window time.Duration
	now    func() time.Time

	mu   sync.Mutex
	seen map[string][]time.Time
}

// NewLimiter locks a key out after max failures within window.
func NewLimiter(max int, window time.Duration) *Limiter {
	return &Limiter{max: max, window: window, now: time.Now, seen: map[string][]time.Time{}}
}

// Locked reports whether key has failed max times within the window,
// forgetting older failures as it goes.
func (l *Limiter) Locked(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	cut := l.now().Add(-l.window)
	kept := l.seen[key][:0]
	for _, at := range l.seen[key] {
		if at.After(cut) {
			kept = append(kept, at)
		}
	}
	if len(kept) == 0 {
		delete(l.seen, key)
	} else {
		l.seen[key] = kept
	}
	return len(kept) >= l.max
}

// Fail records one failure for key.
func (l *Limiter) Fail(key string) {
	l.mu.Lock()
	l.seen[key] = append(l.seen[key], l.now())
	l.mu.Unlock()
}
