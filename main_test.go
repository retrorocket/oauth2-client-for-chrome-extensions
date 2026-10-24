package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/sessions"
	"github.com/labstack/echo-contrib/v5/session"
	"github.com/labstack/echo/v5"
)

func TestRequestLogger(t *testing.T) {
	for _, tc := range []struct {
		name    string
		handler echo.HandlerFunc
		status  int
		body    string
		errText string
	}{
		{"success", func(c *echo.Context) error { return c.String(http.StatusOK, "ok") }, http.StatusOK, "ok", ""},
		{"redirect", func(c *echo.Context) error { return c.Redirect(http.StatusSeeOther, "/next") }, http.StatusSeeOther, "", ""},
		{"error", func(c *echo.Context) error { return errors.New("exchange failed") }, http.StatusBadGateway, "failed", "exchange failed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := echo.New()
			var output bytes.Buffer
			errorCalls := 0
			e.HTTPErrorHandler = func(c *echo.Context, err error) {
				if response, _ := echo.UnwrapResponse(c.Response()); response != nil && response.Committed {
					return
				}
				errorCalls++
				_ = c.String(http.StatusBadGateway, "failed")
			}
			e.Use(requestLogger(&output))
			e.POST("/test", tc.handler)
			req := httptest.NewRequest(http.MethodPost, "/test?key=value", strings.NewReader("abc"))
			req.Header.Set(echo.HeaderContentLength, "3")
			req.Header.Set(echo.HeaderXRequestID, "request-id")
			req.Header.Set("User-Agent", "test-agent")
			rec := httptest.NewRecorder()
			e.ServeHTTP(rec, req)
			if rec.Code != tc.status || rec.Body.String() != tc.body {
				t.Fatalf("response = %d %q", rec.Code, rec.Body.String())
			}
			if tc.name == "redirect" && rec.Header().Get(echo.HeaderLocation) != "/next" {
				t.Fatal("redirect location changed")
			}
			if tc.errText != "" && errorCalls != 1 {
				t.Fatalf("error responses = %d, want 1", errorCalls)
			}
			var entry map[string]any
			if err := json.Unmarshal(output.Bytes(), &entry); err != nil {
				t.Fatalf("invalid log: %v: %s", err, output.String())
			}
			if len(entry) != 13 {
				t.Fatalf("log fields = %d, want 13", len(entry))
			}
			for key, want := range map[string]any{
				"id": "request-id", "remote_ip": "192.0.2.1", "host": "example.com",
				"method": "POST", "uri": "/test?key=value", "user_agent": "test-agent",
				"status": float64(tc.status), "error": tc.errText,
				"bytes_in": float64(3), "bytes_out": float64(len(tc.body)),
			} {
				if entry[key] != want {
					t.Errorf("log %s = %v, want %v", key, entry[key], want)
				}
			}
			if _, err := time.Parse(time.RFC3339Nano, entry["time"].(string)); err != nil {
				t.Errorf("invalid log time: %v", err)
			}
			latency, err := time.ParseDuration(entry["latency_human"].(string))
			if err != nil || float64(latency) != entry["latency"] {
				t.Errorf("inconsistent log latency: %v", entry)
			}
		})
	}
}

type testSessionStore struct {
	getErr      error
	saveErr     error
	nilSession  bool
	saved       int
	maxAge      int
	values      map[interface{}]interface{}
	savedValues map[interface{}]interface{}
}

func (s *testSessionStore) Get(r *http.Request, name string) (*sessions.Session, error) {
	return s.New(r, name)
}

func (s *testSessionStore) New(_ *http.Request, name string) (*sessions.Session, error) {
	if s.nilSession {
		return nil, s.getErr
	}
	sess := sessions.NewSession(s, name)
	sess.Options = &sessions.Options{MaxAge: 300}
	sess.Values["state"] = "valid-state"
	sess.Values["code_verifier"] = strings.Repeat("v", 43)
	if s.values != nil {
		sess.Values = s.values
	}
	return sess, s.getErr
}

func (s *testSessionStore) Save(_ *http.Request, _ http.ResponseWriter, sess *sessions.Session) error {
	s.saved++
	s.maxAge = sess.Options.MaxAge
	s.savedValues = sess.Values
	return s.saveErr
}

type testRoundTripper func(*http.Request) (*http.Response, error)

func (f testRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func TestOAuthSessionErrors(t *testing.T) {
	sessionErr := errors.New("session store failure")
	for _, tc := range []struct {
		name       string
		handler    echo.HandlerFunc
		getErr     error
		saveErr    error
		nilSession bool
		wantSaves  int
		wantTokens int
	}{
		{"redirect get error", GetRedirectUrl, sessionErr, nil, false, 0, 0},
		{"redirect nil session", GetRedirectUrl, sessionErr, nil, true, 0, 0},
		{"redirect save error", GetRedirectUrl, nil, sessionErr, false, 1, 0},
		{"callback get error", GetToken, sessionErr, nil, false, 0, 0},
		{"callback nil session", GetToken, sessionErr, nil, true, 0, 0},
		{"callback save error", GetToken, nil, sessionErr, false, 1, 1},
		{"redirect success", GetRedirectUrl, nil, nil, false, 1, 0},
		{"callback success", GetToken, nil, nil, false, 1, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tokenCalls := 0
			originalClient := http.DefaultClient
			t.Cleanup(func() { http.DefaultClient = originalClient })
			http.DefaultClient = &http.Client{Transport: testRoundTripper(func(r *http.Request) (*http.Response, error) {
				tokenCalls++
				if err := r.ParseForm(); err != nil {
					t.Fatal(err)
				}
				if r.Form.Get("code_verifier") != strings.Repeat("v", 43) {
					t.Fatal("token exchange must include the session's PKCE verifier")
				}
				return &http.Response{
					StatusCode: http.StatusOK,
					Header:     http.Header{"Content-Type": []string{"application/json"}},
					Body:       io.NopCloser(strings.NewReader(`{"access_token":"test-token","token_type":"Bearer"}`)),
					Request:    r,
				}, nil
			})}
			store := &testSessionStore{getErr: tc.getErr, saveErr: tc.saveErr, nilSession: tc.nilSession}
			e := echo.New()
			rec := httptest.NewRecorder()
			c := e.NewContext(httptest.NewRequest(http.MethodGet, "/?state=valid-state&code=test-code", nil), rec)
			err := session.Middleware(store)(tc.handler)(c)
			if tc.getErr != nil || tc.saveErr != nil {
				if !errors.Is(err, sessionErr) {
					t.Fatalf("error = %v, want session error", err)
				}
				response, unwrapErr := echo.UnwrapResponse(c.Response())
				if unwrapErr != nil {
					t.Fatal(unwrapErr)
				}
				if response.Committed || rec.Header().Get("Location") != "" || rec.Body.Len() != 0 {
					t.Fatal("session failure must not send an OAuth redirect or token")
				}
			} else if err != nil || rec.Code != http.StatusSeeOther || rec.Header().Get("Location") == "" {
				t.Fatalf("success response = %d, error = %v", rec.Code, err)
			}
			if store.saved != tc.wantSaves || tokenCalls != tc.wantTokens {
				t.Errorf("save/token calls = %d/%d, want %d/%d", store.saved, tokenCalls, tc.wantSaves, tc.wantTokens)
			}
			if tc.wantTokens == 1 && store.maxAge != -1 {
				t.Error("callback must save session invalidation")
			}
			if tc.wantTokens == 1 {
				if _, ok := store.savedValues["code_verifier"]; ok {
					t.Error("callback must remove the verifier from the session")
				}
				if _, ok := store.savedValues["state"]; ok {
					t.Error("callback must remove state from the session")
				}
			}
		})
	}
}

func TestRequestLoggerClientIP(t *testing.T) {
	for _, tc := range []struct {
		name, peer, forwarded, want string
	}{
		{"local proxy", "127.0.0.1:12345", "203.0.113.10", "203.0.113.10"},
		{"IPv6 local proxy", "[::1]:12345", "2001:db8::10", "2001:db8::10"},
		{"forged prefix", "127.0.0.1:12345", "198.51.100.99, 203.0.113.10", "203.0.113.10"},
		{"direct request", "203.0.113.10:12345", "198.51.100.99", "203.0.113.10"},
		{"untrusted private peer", "10.0.0.1:12345", "198.51.100.99", "10.0.0.1"},
		{"untrusted link local peer", "169.254.1.1:12345", "198.51.100.99", "169.254.1.1"},
		{"no header", "127.0.0.1:12345", "", "127.0.0.1"},
		{"invalid header", "127.0.0.1:12345", "invalid", "127.0.0.1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := echo.New()
			e.IPExtractor = clientIPExtractor()
			var output bytes.Buffer
			e.Use(requestLogger(&output))
			e.GET("/try", func(c *echo.Context) error { return c.NoContent(http.StatusNoContent) })
			req := httptest.NewRequest(http.MethodGet, "/try", nil)
			req.RemoteAddr = tc.peer
			if tc.forwarded != "" {
				req.Header.Set(echo.HeaderXForwardedFor, tc.forwarded)
			}
			e.ServeHTTP(httptest.NewRecorder(), req)
			var entry struct {
				RemoteIP string `json:"remote_ip"`
			}
			if err := json.Unmarshal(output.Bytes(), &entry); err != nil {
				t.Fatal(err)
			}
			if entry.RemoteIP != tc.want {
				t.Errorf("remote_ip = %q, want %q", entry.RemoteIP, tc.want)
			}
		})
	}
}

func TestRequestLoggerOmitsCallbackQuery(t *testing.T) {
	for _, status := range []int{http.StatusSeeOther, http.StatusForbidden, http.StatusInternalServerError} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			e := echo.New()
			var output bytes.Buffer
			e.Use(requestLogger(&output))
			e.GET("/oauth2", func(c *echo.Context) error {
				if c.QueryParam("code") != "secret-code" || c.QueryParam("state") != "secret-state" {
					t.Fatal("logger changed the callback query")
				}
				if status == http.StatusInternalServerError {
					return errors.New("exchange failed")
				}
				return c.NoContent(status)
			})
			req := httptest.NewRequest(http.MethodGet, "/oauth2?code=secret-code&state=secret-state&scope=private-scope", nil)
			rec := httptest.NewRecorder()
			e.ServeHTTP(rec, req)
			if rec.Code != status {
				t.Fatalf("status = %d, want %d", rec.Code, status)
			}
			var entry map[string]any
			if err := json.Unmarshal(output.Bytes(), &entry); err != nil {
				t.Fatal(err)
			}
			if entry["uri"] != "/oauth2" {
				t.Errorf("uri = %v, want /oauth2", entry["uri"])
			}
			for _, secret := range []string{"secret-code", "secret-state", "private-scope"} {
				if strings.Contains(output.String(), secret) {
					t.Errorf("callback query leaked into log: %s", secret)
				}
			}
		})
	}
}

func TestPKCEAuthorization(t *testing.T) {
	var previousVerifier string
	for i := 0; i < 2; i++ {
		store := &testSessionStore{}
		e := echo.New()
		rec := httptest.NewRecorder()
		c := e.NewContext(httptest.NewRequest(http.MethodGet, "/try", nil), rec)
		if err := session.Middleware(store)(GetRedirectUrl)(c); err != nil {
			t.Fatal(err)
		}
		location, err := url.Parse(rec.Header().Get("Location"))
		if err != nil {
			t.Fatal(err)
		}
		verifier, _ := store.savedValues["code_verifier"].(string)
		if len(verifier) < 43 || len(verifier) > 128 || verifier == previousVerifier {
			t.Fatal("expected a fresh PKCE verifier of valid length")
		}
		previousVerifier = verifier
		digest := sha256.Sum256([]byte(verifier))
		query := location.Query()
		if query.Get("code_challenge_method") != "S256" || query.Get("code_challenge") != base64.RawURLEncoding.EncodeToString(digest[:]) {
			t.Fatal("authorization request must contain the verifier's S256 challenge")
		}
		if query.Get("state") == "" || query.Get("state") != store.savedValues["state"] {
			t.Fatal("authorization state must match the session")
		}
		if strings.Contains(location.String(), verifier) {
			t.Fatal("authorization redirect must not expose the verifier")
		}
	}
}

func TestPKCECallbackRejectsInvalidSession(t *testing.T) {
	for _, tc := range []struct {
		name   string
		values map[interface{}]interface{}
		query  string
	}{
		{"missing verifier", map[interface{}]interface{}{"state": "valid-state"}, "state=valid-state&code=test-code"},
		{"empty verifier", map[interface{}]interface{}{"state": "valid-state", "code_verifier": ""}, "state=valid-state&code=test-code"},
		{"invalid verifier type", map[interface{}]interface{}{"state": "valid-state", "code_verifier": 123}, "state=valid-state&code=test-code"},
		{"missing state", map[interface{}]interface{}{"code_verifier": strings.Repeat("v", 43)}, "code=test-code"},
		{"mismatched state", nil, "state=wrong-state&code=test-code"},
		{"missing code", nil, "state=valid-state"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			originalClient := http.DefaultClient
			t.Cleanup(func() { http.DefaultClient = originalClient })
			http.DefaultClient = &http.Client{Transport: testRoundTripper(func(r *http.Request) (*http.Response, error) {
				t.Fatal("invalid callback must not contact the token endpoint")
				return nil, errors.New("unexpected token exchange")
			})}
			store := &testSessionStore{values: tc.values}
			e := echo.New()
			rec := httptest.NewRecorder()
			c := e.NewContext(httptest.NewRequest(http.MethodGet, "/oauth2?"+tc.query, nil), rec)
			if err := session.Middleware(store)(GetToken)(c); err != nil {
				t.Fatal(err)
			}
			if rec.Code != http.StatusForbidden || store.saved != 0 {
				t.Fatalf("status/saves = %d/%d, want 403/0", rec.Code, store.saved)
			}
		})
	}
}
