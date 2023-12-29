package main

import (
	"math/rand"
	"net/http"
	"os"

	"github.com/gorilla/securecookie"
	"github.com/gorilla/sessions"
	"github.com/labstack/echo-contrib/session"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
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
)

func RandomString(n int) string {
	var letters = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")

	s := make([]rune, n)
	for i := range s {
		s[i] = letters[rand.Intn(len(letters))]
	}
	return string(s)
}

func GetRedirectUrl(c echo.Context) error {
	sess, _ := session.Get("session", c)
	sess.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   60 * 5,
		HttpOnly: true,
		Secure:   true,
	}
	state := RandomString(20)
	sess.Values["state"] = state
	err := sess.Save(c.Request(), c.Response())
	if err != nil {
		return err
	}

	return c.Redirect(http.StatusSeeOther, config.AuthCodeURL(state, oauth2.AccessTypeOnline))
}

func GetToken(c echo.Context) error {
	stateParam := c.QueryParam("state")
	sess, _ := session.Get("session", c)
	state, _ := sess.Values["state"]
	if state != stateParam {
		return c.NoContent(http.StatusForbidden)
	}
	code := c.QueryParam("code")
	if code == "" {
		return c.NoContent(http.StatusForbidden)
	}
	token, err := config.Exchange(oauth2.NoContext, code)
	if err != nil {
		return err
	}
	return c.Redirect(http.StatusSeeOther, "https://"+extentionId+".chromiumapp.org/callback#token="+token.AccessToken)
}

type Post struct {
	App string `json:"app"`
}

type Result struct {
	Token string `json:"access_token"`
}

func ResponseToken(c echo.Context) error {
	post := new(Post)
	if err := c.Bind(post); err != nil {
		return err
	}
	extentionId := os.Getenv("RC_EXTENSION_ID")
	if c.Request().Header.Get("Origin") != "chrome-extension://"+extentionId {
		return c.NoContent(http.StatusForbidden)
	}
	sess, _ := session.Get("session", c)
	token, _ := sess.Values["token"]
	sess.Options.MaxAge = -1
	err := sess.Save(c.Request(), c.Response())
	if err != nil {
		return err
	}
	result := &Result{
		Token: token.(string),
	}
	return c.JSON(http.StatusOK, result)
}

func main() {
	router := NewRouter()
	// Start server
	router.Logger.Fatal(router.Start(":18199"))
}

func NewRouter() *echo.Echo {
	// Echo instance
	e := echo.New()
	store, err := redisStore.NewRediStore(10, "tcp", ":6379", "", []byte(securecookie.GenerateRandomKey(32)))
	if err != nil {
		panic(err)
	}
	e.Use(session.Middleware(store))

	// Setting CORS
	extentionId := os.Getenv("RC_EXTENSION_ID")
	e.Use(middleware.CORSWithConfig(middleware.CORSConfig{
		AllowOrigins: []string{"chrome-extension://" + extentionId, "extension://" + extentionId},
		AllowMethods: []string{http.MethodGet, http.MethodPost},
	}))

	// Middleware
	e.Use(middleware.Logger())
	e.Use(middleware.Recover())

	// Routes
	e.GET("/try", GetRedirectUrl)
	e.GET("/oauth2", GetToken)

	return e
}
