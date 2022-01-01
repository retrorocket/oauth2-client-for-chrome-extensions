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
		RedirectURL:  "https://rcapi.retrorocket.biz/oauth2",
		Scopes:       []string{"https://www.googleapis.com/auth/calendar"},
		Endpoint: oauth2.Endpoint{
			AuthURL:  "https://accounts.google.com/o/oauth2/auth",
			TokenURL: "https://accounts.google.com/o/oauth2/token",
		},
	}
)

func RandomString(n int) string {
	var letters = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")

	s := make([]rune, n)
	for i := range s {
		s[i] = letters[rand.Intn(len(letters))]
	}
	return string(s)
}

func main() {
	// Echo instance
	e := echo.New()
	store, err := redisStore.NewRediStore(10, "tcp", ":6379", "", []byte(securecookie.GenerateRandomKey(32)))
	if err != nil {
		panic(err)
	}
	e.Use(session.Middleware(store))

	// Middleware
	e.Use(middleware.Logger())
	e.Use(middleware.Recover())

	// Routes
	e.GET("/try", func(c echo.Context) error {

		sess, _ := session.Get("session", c)
		sess.Options = &sessions.Options{
			Path:     "/",
			MaxAge:   60 * 5,
			HttpOnly: true,
		}
		state := RandomString(20)
		sess.Values["state"] = state
		if err = sess.Save(c.Request(), c.Response()); err != nil {
			return err
		}

		return c.Redirect(http.StatusSeeOther, config.AuthCodeURL(state))
	})

	// Routes
	e.GET("/oauth2", func(c echo.Context) error {

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
		sess.Options.MaxAge = -1
		if err = sess.Save(c.Request(), c.Response()); err != nil {
			return err
		}
		return c.Redirect(http.StatusSeeOther, "https://mlcpcfkgkgnpfmjplcjcegkolppjeaoa.chromiumapp.org#access_token="+token.AccessToken)

	})

	// Start server
	e.Logger.Fatal(e.Start(":18099"))

}
