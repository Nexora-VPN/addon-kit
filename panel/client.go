// Package panel is a small client for the panel's /api/v1, with the token an
// addon was given at registration. It speaks JSON, sends an Idempotency-Key
// when asked to, waits once on a 429, and turns an error answer into an
// *Error. It does not model the API: the routes and their bodies are the
// panel's openapi.yaml (served at /api/openapi.json).
package panel

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Client calls one panel with one token.
type Client struct {
	// Base is the panel's address, as the credentials carry it.
	Base  string
	Token string
	// HTTP is the client used; nil is a client with a 30-second timeout.
	HTTP *http.Client
}

// Error is an answer outside 2xx.
type Error struct {
	Status  int
	Message string
}

func (e *Error) Error() string { return fmt.Sprintf("panel answered %d: %s", e.Status, e.Message) }

// IsStatus reports whether err is an *Error with that status.
func IsStatus(err error, status int) bool {
	var e *Error
	return errors.As(err, &e) && e.Status == status
}

// Request is one call.
type Request struct {
	Method string
	// Path is under /api/v1, e.g. "/users?contact_telegram_id=42".
	Path string
	// Body is marshalled to JSON when not nil.
	Body any
	// IdempotencyKey makes a retried write safe: the panel answers a repeat
	// with the first answer instead of running it again. Derive it from what
	// the write is for (an order id), never at random per attempt.
	IdempotencyKey string
}

// Do runs a request and decodes a 2xx answer into out (nil to discard).
func (c *Client) Do(ctx context.Context, req Request, out any) error {
	var body []byte
	if req.Body != nil {
		var err error
		if body, err = json.Marshal(req.Body); err != nil {
			return err
		}
	}
	for attempt := 0; ; attempt++ {
		resp, err := c.send(ctx, req, body)
		if err != nil {
			return err
		}
		if resp.StatusCode == http.StatusTooManyRequests && attempt == 0 {
			wait := retryAfter(resp.Header.Get("Retry-After"))
			resp.Body.Close()
			select {
			case <-time.After(wait):
				continue
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		defer resp.Body.Close()
		raw, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
		if err != nil {
			return err
		}
		if resp.StatusCode < 200 || resp.StatusCode > 299 {
			var e struct {
				Error string `json:"error"`
			}
			_ = json.Unmarshal(raw, &e)
			if e.Error == "" {
				e.Error = strings.TrimSpace(string(raw))
			}
			return &Error{Status: resp.StatusCode, Message: e.Error}
		}
		if out == nil || len(raw) == 0 {
			return nil
		}
		return json.Unmarshal(raw, out)
	}
}

func (c *Client) send(ctx context.Context, req Request, body []byte) (*http.Response, error) {
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	method := req.Method
	if method == "" {
		method = http.MethodGet
	}
	hr, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(c.Base, "/")+"/api/v1"+req.Path, rd)
	if err != nil {
		return nil, err
	}
	hr.Header.Set("Authorization", "Bearer "+c.Token)
	hr.Header.Set("Accept", "application/json")
	if body != nil {
		hr.Header.Set("Content-Type", "application/json")
	}
	if req.IdempotencyKey != "" {
		hr.Header.Set("Idempotency-Key", req.IdempotencyKey)
	}
	hc := c.HTTP
	if hc == nil {
		hc = &http.Client{Timeout: 30 * time.Second}
	}
	return hc.Do(hr)
}

func retryAfter(v string) time.Duration {
	if s, err := strconv.Atoi(strings.TrimSpace(v)); err == nil && s > 0 && s <= 60 {
		return time.Duration(s) * time.Second
	}
	return 2 * time.Second
}

// Get, Post, Put and Delete are Do for one method.
func (c *Client) Get(ctx context.Context, path string, out any) error {
	return c.Do(ctx, Request{Method: http.MethodGet, Path: path}, out)
}

func (c *Client) Post(ctx context.Context, path string, body any, idempotencyKey string, out any) error {
	return c.Do(ctx, Request{Method: http.MethodPost, Path: path, Body: body, IdempotencyKey: idempotencyKey}, out)
}

func (c *Client) Put(ctx context.Context, path string, body any, out any) error {
	return c.Do(ctx, Request{Method: http.MethodPut, Path: path, Body: body}, out)
}

func (c *Client) Delete(ctx context.Context, path string) error {
	return c.Do(ctx, Request{Method: http.MethodDelete, Path: path}, nil)
}

// Me is GET /api/v1/me: who the token is. A cheap check that the
// credentials still work.
func (c *Client) Me(ctx context.Context) (map[string]any, error) {
	var me map[string]any
	return me, c.Get(ctx, "/me", &me)
}
