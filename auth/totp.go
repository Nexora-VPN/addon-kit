package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // RFC 6238 TOTP is defined over HMAC-SHA1; every authenticator app speaks it
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// Time-based one-time passwords, RFC 6238 over RFC 4226, from the standard
// library alone — the panel's own parameters, so an admin's authenticator
// app treats an addon and the panel the same way: HMAC-SHA1, a 30-second
// step, six digits, one step of skew either side. VerifyTOTP refuses a step
// at or below the last one accepted, so a code cannot be used twice.

const (
	totpStep        = 30 * time.Second
	totpDigits      = 6
	totpSkew        = 1
	totpSecretBytes = 20
)

// ClockOffset lets tests step through time steps instead of sleeping.
var ClockOffset time.Duration

// Now is the TOTP clock.
func Now() time.Time { return time.Now().Add(ClockOffset) }

var totpEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// NewTOTPSecret returns a fresh base32 secret.
func NewTOTPSecret() (string, error) {
	buf := make([]byte, totpSecretBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return totpEncoding.EncodeToString(buf), nil
}

// TOTPURI is the otpauth:// URI an authenticator app enrols from, labelled
// "<issuer>:<username>" — the addon's name as the app lists it.
func TOTPURI(issuer, username, secret string) string {
	q := url.Values{}
	q.Set("secret", secret)
	q.Set("issuer", issuer)
	q.Set("algorithm", "SHA1")
	q.Set("digits", fmt.Sprint(totpDigits))
	q.Set("period", fmt.Sprint(int(totpStep.Seconds())))
	return "otpauth://totp/" + url.PathEscape(issuer+":"+username) + "?" + q.Encode()
}

func hotp(secret []byte, counter int64) string {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(counter))
	mac := hmac.New(sha1.New, secret)
	mac.Write(msg[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	code := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff
	return fmt.Sprintf("%06d", code%1000000)
}

// TOTPCode is the code for a secret at a moment (tests, and nothing else).
func TOTPCode(secret string, at time.Time) string {
	key, _ := totpEncoding.DecodeString(secret)
	return hotp(key, at.Unix()/int64(totpStep.Seconds()))
}

// VerifyTOTP checks a code, accepting one step either side, and reports the
// step it matched; lastUsed is the highest step already accepted, and
// anything at or below it is refused.
func VerifyTOTP(secret, code string, now time.Time, lastUsed int64) (int64, bool) {
	key, err := totpEncoding.DecodeString(strings.ToUpper(strings.TrimSpace(secret)))
	if err != nil {
		return 0, false
	}
	code = strings.ReplaceAll(strings.TrimSpace(code), " ", "")
	if len(code) != totpDigits {
		return 0, false
	}
	base := now.Unix() / int64(totpStep.Seconds())
	for delta := int64(-totpSkew); delta <= totpSkew; delta++ {
		counter := base + delta
		if counter <= lastUsed {
			continue
		}
		if subtle.ConstantTimeCompare([]byte(hotp(key, counter)), []byte(code)) == 1 {
			return counter, true
		}
	}
	return 0, false
}
