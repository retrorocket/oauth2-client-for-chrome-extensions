package main

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"time"

	"github.com/gorilla/securecookie"
	"github.com/gorilla/sessions"
	"github.com/labstack/echo-contrib/v5/session"
	"github.com/labstack/echo/v5"
	"github.com/labstack/echo/v5/middleware"
	"golang.org/x/oauth2"
	redisStore "gopkg.in/boj/redistore.v1"
)

var (
	config = oauth2.Config{
		ClientID:     os.Getenv("RC_CLIENT_ID"),
		ClientSecret: os.Getenv("RC_CLIENT_SECRET"),
		RedirectURL:  os.Getenv("RC_REDIRECT_URL"),
		Scopes: []string{
			"https://www.googleapis.com/auth/calendar.events",
			"https://www.googleapis.com/auth/calendar.readonly",
		},
		Endpoint: oauth2.Endpoint{
			AuthURL:  "https://accounts.google.com/o/oauth2/v2/auth",
			TokenURL: "https://oauth2.googleapis.com/token",
		},
	}
	extentionId = os.Getenv("RC_EXTENSION_ID")
	appUrl      = "https://" + extentionId + ".chromiumapp.org/callback"
)

func RandomString(n int) (string, error) {
	var letters = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
	limit := big.NewInt(int64(len(letters)))

	s := make([]rune, n)
	for i := range s {
		index, err := rand.Int(rand.Reader, limit)
		if err != nil {
			return "", err
		}
		s[i] = letters[index.Int64()]
	}
	return string(s), nil
}

func GetRedirectUrl(c *echo.Context) error {
	sess, err := session.Get("session", c)
	if err != nil {
		return err
	}
	sess.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   60 * 5,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	}
	state, err := RandomString(20)
	if err != nil {
		return err
	}
	sess.Values["state"] = state
	verifier := oauth2.GenerateVerifier()
	sess.Values["code_verifier"] = verifier
	err = sess.Save(c.Request(), c.Response())
	if err != nil {
		return err
	}

	return c.Redirect(http.StatusSeeOther, config.AuthCodeURL(state, oauth2.AccessTypeOnline, oauth2.S256ChallengeOption(verifier)))
}

func GetToken(c *echo.Context) error {
	stateParam := c.QueryParam("state")
	sess, err := session.Get("session", c)
	if err != nil {
		return err
	}
	state, _ := sess.Values["state"].(string)
	if state == "" || state != stateParam {
		return c.NoContent(http.StatusForbidden)
	}
	verifier, _ := sess.Values["code_verifier"].(string)

	// state と code_verifier は一度きりの値なので、トークン交換より前に破棄する。
	// 交換の失敗・認可拒否（error=access_denied）・再送のいずれでも再利用させない。
	if sess.Options == nil {
		sess.Options = &sessions.Options{Path: "/"}
	}
	sess.Options.MaxAge = -1
	delete(sess.Values, "state")
	delete(sess.Values, "code_verifier")
	if err := sess.Save(c.Request(), c.Response()); err != nil {
		return err
	}

	if verifier == "" {
		return c.NoContent(http.StatusForbidden)
	}
	code := c.QueryParam("code")
	if code == "" {
		return c.NoContent(http.StatusForbidden)
	}
	token, err := config.Exchange(c.Request().Context(), code, oauth2.VerifierOption(verifier))
	if err != nil {
		return err
	}

	return c.Redirect(http.StatusSeeOther, appUrl+"#token="+token.AccessToken)
}

// Chrome 拡張 ID は a〜p の32文字。不正な値のままだとトークンの返却先 URL が
// 意図しないホストになり得るため、起動時に拒否する。
var extensionIDPattern = regexp.MustCompile(`^[a-p]{32}$`)

func main() {
	if !extensionIDPattern.MatchString(extentionId) {
		fmt.Fprintln(os.Stderr, "RC_EXTENSION_ID must be a 32-character Chrome extension ID")
		os.Exit(1)
	}
	router := NewRouter()
	// Start server
	if err := router.Start(":28199"); err != nil && !errors.Is(err, http.ErrServerClosed) {
		router.Logger.Error("server stopped", "error", err)
		os.Exit(1)
	}
}

func NewRouter() *echo.Echo {
	// Echo instance
	e := echo.New()
	e.IPExtractor = clientIPExtractor()
	store, err := redisStore.NewRediStore(10, "tcp", ":6379", "", []byte(securecookie.GenerateRandomKey(32)))
	if err != nil {
		panic(err)
	}
	e.Use(session.Middleware(store))

	// Middleware
	e.Use(requestLogger(os.Stdout))
	e.Use(noStoreHeaders)
	e.Use(middleware.Recover())

	// Routes
	e.GET("/try", GetRedirectUrl)
	e.GET("/oauth2", GetToken)

	return e
}

// レスポンスの Location にはアクセストークンや state が含まれるため、
// ブラウザ・リバースプロキシにキャッシュさせず、Referer にも載せない（RFC 6749 5.1）。
func noStoreHeaders(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c *echo.Context) error {
		h := c.Response().Header()
		h.Set(echo.HeaderCacheControl, "no-store")
		h.Set("Pragma", "no-cache")
		h.Set("Referrer-Policy", "no-referrer")
		return next(c)
	}
}

// Only the local reverse proxy may supply forwarded client addresses.
func clientIPExtractor() echo.IPExtractor {
	return echo.ExtractIPFromXFFHeader(
		echo.TrustLoopback(true),
		echo.TrustPrivateNet(false),
		echo.TrustLinkLocal(false),
	)
}

func requestLogger(output io.Writer) echo.MiddlewareFunc {
	return middleware.RequestLoggerWithConfig(middleware.RequestLoggerConfig{
		HandleError:      true,
		LogLatency:       true,
		LogRequestID:     true,
		LogRemoteIP:      true,
		LogHost:          true,
		LogMethod:        true,
		LogURI:           true,
		LogUserAgent:     true,
		LogStatus:        true,
		LogContentLength: true,
		LogResponseSize:  true,
		LogValuesFunc: func(c *echo.Context, v middleware.RequestLoggerValues) error {
			errorMessage := ""
			if v.Error != nil {
				errorMessage = v.Error.Error()
			}
			// クエリ文字列は記録しない。コールバックの code / state / scope は
			// 認可情報であり、パス表記の揺れ（/oauth2/ 等）でも漏れないよう全リクエスト共通で落とす。
			uri := c.Request().URL.EscapedPath()
			bytesIn, _ := strconv.ParseInt(v.ContentLength, 10, 64)
			// Preserve the previous logger's JSON fields and output destination.
			return json.NewEncoder(output).Encode(struct {
				Time         string        `json:"time"`
				ID           string        `json:"id"`
				RemoteIP     string        `json:"remote_ip"`
				Host         string        `json:"host"`
				Method       string        `json:"method"`
				URI          string        `json:"uri"`
				UserAgent    string        `json:"user_agent"`
				Status       int           `json:"status"`
				Error        string        `json:"error"`
				Latency      time.Duration `json:"latency"`
				LatencyHuman string        `json:"latency_human"`
				BytesIn      int64         `json:"bytes_in"`
				BytesOut     int64         `json:"bytes_out"`
			}{
				Time: time.Now().Format(time.RFC3339Nano), ID: v.RequestID,
				RemoteIP: v.RemoteIP, Host: v.Host, Method: v.Method, URI: uri,
				UserAgent: v.UserAgent, Status: v.Status, Error: errorMessage,
				Latency: v.Latency, LatencyHuman: v.Latency.String(),
				BytesIn: bytesIn, BytesOut: v.ResponseSize,
			})
		},
	})
}
