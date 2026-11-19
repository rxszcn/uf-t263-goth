// Command stateboundary drives gothic.CompleteUserAuth against the four
// callback shapes from the boundary input table:
//
//	1. missing state  : callback URL has no state parameter
//	2. empty state    : callback URL carries state=
//	3. wrong state    : callback URL carries a non-matching state
//	4. normal state   : callback URL carries the state established at BeginAuth
//
// It prints the observed error text (or "<nil>") per shape so the delivery
// document can record the constructed measurements.
package main

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"

	"github.com/gorilla/sessions"
	"github.com/markbates/goth"
	"github.com/markbates/goth/gothic"
	"github.com/markbates/goth/providers/faux"
)

type mapKey struct {
	r *http.Request
	n string
}

type providerStore struct {
	store map[mapKey]*sessions.Session
}

func newProviderStore() *providerStore {
	return &providerStore{map[mapKey]*sessions.Session{}}
}

func (p providerStore) Get(r *http.Request, name string) (*sessions.Session, error) {
	s := p.store[mapKey{r, name}]
	if s == nil {
		return p.New(r, name)
	}
	return s, nil
}

func (p providerStore) New(r *http.Request, name string) (*sessions.Session, error) {
	s := sessions.NewSession(p, name)
	s.Options = &sessions.Options{Path: "/", MaxAge: 86400 * 30}
	p.store[mapKey{r, name}] = s
	return s, nil
}

func (p providerStore) Save(r *http.Request, w http.ResponseWriter, s *sessions.Session) error {
	p.store[mapKey{r, s.Name()}] = s
	return nil
}

func gzipString(value string) string {
	var b bytes.Buffer
	gz := gzip.NewWriter(&b)
	_, _ = gz.Write([]byte(value))
	_ = gz.Flush()
	_ = gz.Close()
	return b.String()
}

func main() {
	provider := &faux.Provider{}
	goth.UseProviders(provider)

	const originalState = "state_REAL"

	shapes := []struct {
		name    string
		callback string
	}{
		{"missing state", "/auth/callback?provider=faux"},
		{"empty state", "/auth/callback?provider=faux&state="},
		{"wrong state", "/auth/callback?provider=faux&state=state_FAKE"},
		{"normal state", "/auth/callback?provider=faux&state=" + originalState},
	}

	failed := false
	for _, shape := range shapes {
		gothic.Store = newProviderStore()
		res := httptest.NewRecorder()

		// Establish the session exactly as BeginAuth would: a faux session whose
		// AuthURL carries the original state, loaded directly into the store to
		// avoid any network dependency.
		beginSess := faux.Session{
			ID:      "id",
			AuthURL: "http://example.com/auth?state=" + originalState,
		}
		req, err := http.NewRequest("GET", shape.callback, nil)
		if err != nil {
			panic(err)
		}
		session, _ := gothic.Store.Get(req, gothic.SessionName)
		session.Values["faux"] = gzipString(beginSess.Marshal())
		if err := session.Save(req, res); err != nil {
			panic(err)
		}

		_, err = gothic.CompleteUserAuth(res, req)

		var observed string
		if err == nil {
			observed = "<nil> (login silently completed)"
		} else {
			observed = err.Error()
		}
		fmt.Printf("shape=%-13q callback=%-45s error=%s\n", shape.name, shape.callback, observed)

		switch shape.name {
		case "normal state":
			if err != nil {
				failed = true
			}
		default:
			if err == nil {
				failed = true
			}
		}
	}

	if failed {
		fmt.Println("RESULT: FAIL (a rejected shape was accepted or the normal flow broke)")
		os.Exit(1)
	}
	fmt.Println("RESULT: PASS (missing/empty/wrong rejected, normal accepted)")
}
