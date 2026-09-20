package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/sessions"
	"github.com/labstack/echo-contrib/session"
	"github.com/labstack/echo/v4"
)

func TestRequestLogger(t *testing.T) {
	for _, tc := range []struct {
		name    string
		handler echo.HandlerFunc
		status  int
		body    string
		errText string
	}{
		{"success", func(c echo.Context) error { return c.String(http.StatusOK, "ok") }, http.StatusOK, "ok", ""},
		{"redirect", func(c echo.Context) error { return c.Redirect(http.StatusSeeOther, "/next") }, http.StatusSeeOther, "", ""},
		{"error", func(c echo.Context) error { return errors.New("exchange failed") }, http.StatusBadGateway, "failed", "exchange failed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := echo.New()
			var output bytes.Buffer
			e.Logger.SetOutput(&output)
			errorCalls := 0
			e.HTTPErrorHandler = func(err error, c echo.Context) {
				if c.Response().Committed {
					return
				}
				errorCalls++
				_ = c.String(http.StatusBadGateway, "failed")
			}
			e.Use(requestLogger())
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
	getErr     error
	saveErr    error
	nilSession bool
	saved      int
	maxAge     int
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
	return sess, s.getErr
}

func (s *testSessionStore) Save(_ *http.Request, _ http.ResponseWriter, sess *sessions.Session) error {
	s.saved++
	s.maxAge = sess.Options.MaxAge
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
				if c.Response().Committed || rec.Header().Get("Location") != "" || rec.Body.Len() != 0 {
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
		})
	}
}
