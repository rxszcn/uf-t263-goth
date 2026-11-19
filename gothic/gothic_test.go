package gothic_test

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/gorilla/sessions"
	"github.com/markbates/goth"
	. "github.com/markbates/goth/gothic"
	"github.com/markbates/goth/providers/faux"
	"github.com/stretchr/testify/assert"
)

type mapKey struct {
	r *http.Request
	n string
}

type ProviderStore struct {
	Store map[mapKey]*sessions.Session
}

func NewProviderStore() *ProviderStore {
	return &ProviderStore{map[mapKey]*sessions.Session{}}
}

func (p ProviderStore) Get(r *http.Request, name string) (*sessions.Session, error) {
	s := p.Store[mapKey{r, name}]
	if s == nil {
		s, err := p.New(r, name)
		return s, err
	}
	return s, nil
}

func (p ProviderStore) New(r *http.Request, name string) (*sessions.Session, error) {
	s := sessions.NewSession(p, name)
	s.Options = &sessions.Options{
		Path:   "/",
		MaxAge: 86400 * 30,
	}
	p.Store[mapKey{r, name}] = s
	return s, nil
}

func (p ProviderStore) Save(r *http.Request, w http.ResponseWriter, s *sessions.Session) error {
	p.Store[mapKey{r, s.Name()}] = s
	return nil
}

var fauxProvider goth.Provider

func init() {
	Store = NewProviderStore()
	fauxProvider = &faux.Provider{}
	goth.UseProviders(fauxProvider)
}

func Test_BeginAuthHandler(t *testing.T) {
	a := assert.New(t)

	res := httptest.NewRecorder()
	req, err := http.NewRequest("GET", "/auth?provider=faux", nil)
	a.NoError(err)

	BeginAuthHandler(res, req)

	sess, err := Store.Get(req, SessionName)
	if err != nil {
		t.Fatalf("error getting faux Gothic session: %v", err)
	}

	sessStr, ok := sess.Values["faux"].(string)
	if !ok {
		t.Fatalf("Gothic session not stored as marshalled string; was %T (value %v)",
			sess.Values["faux"], sess.Values["faux"])
	}
	gothSession, err := fauxProvider.UnmarshalSession(ungzipString(sessStr))
	if err != nil {
		t.Fatalf("error unmarshalling faux Gothic session: %v", err)
	}
	au, _ := gothSession.GetAuthURL()

	a.Equal(http.StatusTemporaryRedirect, res.Code)
	a.Contains(res.Body.String(),
		fmt.Sprintf(`<a href="%s">Temporary Redirect</a>`, html.EscapeString(au)))
}

func Test_GetAuthURL(t *testing.T) {
	a := assert.New(t)

	res := httptest.NewRecorder()
	req, err := http.NewRequest("GET", "/auth?provider=faux", nil)
	a.NoError(err)

	u, err := GetAuthURL(res, req)
	a.NoError(err)

	// Check that we get the correct auth URL with a state parameter
	parsed, err := url.Parse(u)
	a.NoError(err)
	a.Equal("http", parsed.Scheme)
	a.Equal("example.com", parsed.Host)
	q := parsed.Query()
	a.Contains(q, "client_id")
	a.Equal("code", q.Get("response_type"))
	a.NotZero(q, "state")

	// Check that if we run GetAuthURL on another request, that request's
	// auth URL has a different state from the previous one.
	req2, err := http.NewRequest("GET", "/auth?provider=faux", nil)
	a.NoError(err)
	url2, err := GetAuthURL(httptest.NewRecorder(), req2)
	a.NoError(err)
	parsed2, err := url.Parse(url2)
	a.NoError(err)
	a.NotEqual(parsed.Query().Get("state"), parsed2.Query().Get("state"))
}

func Test_CompleteUserAuth(t *testing.T) {
	a := assert.New(t)

	res := httptest.NewRecorder()
	req, err := http.NewRequest("GET", "/auth/callback?provider=faux&state=test_state", nil)
	a.NoError(err)

	sess := faux.Session{Name: "Homer Simpson", Email: "homer@example.com", AuthURL: "http://example.com/auth?state=test_state"}
	session, _ := Store.Get(req, SessionName)
	session.Values["faux"] = gzipString(sess.Marshal())
	err = session.Save(req, res)
	a.NoError(err)

	user, err := CompleteUserAuth(res, req)
	a.NoError(err)

	a.Equal(user.Name, "Homer Simpson")
	a.Equal(user.Email, "homer@example.com")
}

func Test_CompleteUserAuthWithSessionDeducedProvider(t *testing.T) {
	a := assert.New(t)

	res := httptest.NewRecorder()
	// Intentionally omit a provider argument, force looking in session.
	req, err := http.NewRequest("GET", "/auth/callback?state=test_state", nil)
	a.NoError(err)

	sess := faux.Session{Name: "Homer Simpson", Email: "homer@example.com", AuthURL: "http://example.com/auth?state=test_state"}
	session, _ := Store.Get(req, SessionName)
	session.Values["faux"] = gzipString(sess.Marshal())
	err = session.Save(req, res)
	a.NoError(err)

	user, err := CompleteUserAuth(res, req)
	a.NoError(err)

	a.Equal(user.Name, "Homer Simpson")
	a.Equal(user.Email, "homer@example.com")
}

func Test_CompleteUserAuthWithContextParamProvider(t *testing.T) {
	a := assert.New(t)

	res := httptest.NewRecorder()
	req, err := http.NewRequest("GET", "/auth/callback?state=test_state", nil)
	a.NoError(err)

	req = GetContextWithProvider(req, "faux")

	sess := faux.Session{Name: "Homer Simpson", Email: "homer@example.com", AuthURL: "http://example.com/auth?state=test_state"}
	session, _ := Store.Get(req, SessionName)
	session.Values["faux"] = gzipString(sess.Marshal())
	err = session.Save(req, res)
	a.NoError(err)

	user, err := CompleteUserAuth(res, req)
	a.NoError(err)

	a.Equal(user.Name, "Homer Simpson")
	a.Equal(user.Email, "homer@example.com")
}

func Test_Logout(t *testing.T) {
	a := assert.New(t)

	res := httptest.NewRecorder()
	req, err := http.NewRequest("GET", "/auth/callback?provider=faux&state=test_state", nil)
	a.NoError(err)

	sess := faux.Session{Name: "Homer Simpson", Email: "homer@example.com", AuthURL: "http://example.com/auth?state=test_state"}
	session, _ := Store.Get(req, SessionName)
	session.Values["faux"] = gzipString(sess.Marshal())
	err = session.Save(req, res)
	a.NoError(err)

	user, err := CompleteUserAuth(res, req)
	a.NoError(err)

	a.Equal(user.Name, "Homer Simpson")
	a.Equal(user.Email, "homer@example.com")
	err = Logout(res, req)
	a.NoError(err)
	session, _ = Store.Get(req, SessionName)
	a.Equal(session.Values, make(map[interface{}]interface{}))
	a.Equal(session.Options.MaxAge, -1)
}

func Test_SetState(t *testing.T) {
	a := assert.New(t)

	req, _ := http.NewRequest("GET", "/auth?state=state", nil)
	a.Equal(SetState(req), "state")
}

func Test_GetState(t *testing.T) {
	a := assert.New(t)

	req, _ := http.NewRequest("GET", "/auth?state=state", nil)
	a.Equal(GetState(req), "state")
}

func Test_StateValidation(t *testing.T) {
	a := assert.New(t)

	Store = NewProviderStore()
	res := httptest.NewRecorder()
	req, err := http.NewRequest("GET", "/auth?provider=faux&state=state_REAL", nil)
	a.NoError(err)

	BeginAuthHandler(res, req)
	session, _ := Store.Get(req, SessionName)

	// Assert that matching states will return a nil error
	req, _ = http.NewRequest("GET", "/auth/callback?provider=faux&state=state_REAL", nil)
	session.Save(req, res)
	_, err = CompleteUserAuth(res, req)
	a.NoError(err)

	// Assert that mismatched states will return an error
	req, _ = http.NewRequest("GET", "/auth/callback?provider=faux&state=state_FAKE", nil)
	session.Save(req, res)
	_, err = CompleteUserAuth(res, req)
	a.Error(err)
}

// Test_StateValidation_MissingStateRejected asserts that a callback request
// without any state parameter is rejected instead of silently completing the
// login. The error must be returned through the normal error path of
// CompleteUserAuth, not swallowed.
func Test_StateValidation_MissingStateRejected(t *testing.T) {
	a := assert.New(t)

	Store = NewProviderStore()
	res := httptest.NewRecorder()
	req, err := http.NewRequest("GET", "/auth?provider=faux&state=state_REAL", nil)
	a.NoError(err)

	BeginAuthHandler(res, req)
	session, _ := Store.Get(req, SessionName)

	// Callback request with the state parameter omitted entirely.
	req, _ = http.NewRequest("GET", "/auth/callback?provider=faux", nil)
	session.Save(req, res)
	_, err = CompleteUserAuth(res, req)
	a.Error(err)
	a.Contains(err.Error(), "state")
}

// Test_StateValidation_EmptyStateRejected asserts that a callback request
// carrying an empty state parameter is rejected with the same strict posture
// as a request where the parameter is missing altogether.
func Test_StateValidation_EmptyStateRejected(t *testing.T) {
	a := assert.New(t)

	Store = NewProviderStore()
	res := httptest.NewRecorder()
	req, err := http.NewRequest("GET", "/auth?provider=faux&state=state_REAL", nil)
	a.NoError(err)

	BeginAuthHandler(res, req)
	session, _ := Store.Get(req, SessionName)

	// Callback request with an explicitly empty state parameter.
	req, _ = http.NewRequest("GET", "/auth/callback?provider=faux&state=", nil)
	session.Save(req, res)
	_, err = CompleteUserAuth(res, req)
	a.Error(err)
	a.Contains(err.Error(), "state")
}

// Test_StateValidation_ValidStatePasses asserts that the normal login flow is
// unchanged: a callback whose state matches the one established during
// BeginAuth completes authentication successfully.
func Test_StateValidation_ValidStatePasses(t *testing.T) {
	a := assert.New(t)

	Store = NewProviderStore()
	res := httptest.NewRecorder()
	req, err := http.NewRequest("GET", "/auth?provider=faux&state=state_REAL", nil)
	a.NoError(err)

	BeginAuthHandler(res, req)
	session, _ := Store.Get(req, SessionName)

	req, _ = http.NewRequest("GET", "/auth/callback?provider=faux&state=state_REAL", nil)
	session.Save(req, res)
	user, err := CompleteUserAuth(res, req)
	a.NoError(err)
	a.NotEmpty(user)
}

// Test_StateValidation_MissingStateInSessionRejected covers the legacy form
// where a session value is loaded directly without going through BeginAuth:
// such a session carries no state, so the callback must be refused rather than
// having the comparison silently skipped.
func Test_StateValidation_MissingStateInSessionRejected(t *testing.T) {
	a := assert.New(t)

	Store = NewProviderStore()
	res := httptest.NewRecorder()
	req, err := http.NewRequest("GET", "/auth/callback?provider=faux&state=state_REAL", nil)
	a.NoError(err)

	// Directly load a session that never went through BeginAuth, so it has
	// no state in its AuthURL.
	sess := faux.Session{Name: "Homer Simpson", Email: "homer@example.com", AuthURL: "http://example.com/auth"}
	session, _ := Store.Get(req, SessionName)
	session.Values["faux"] = gzipString(sess.Marshal())
	a.NoError(session.Save(req, res))

	_, err = CompleteUserAuth(res, req)
	a.Error(err)
	a.Contains(err.Error(), "state")
}

// Test_StateValidation_ProviderIsolation asserts that state tokens are scoped
// to the provider that issued them: a state established during one provider's
// BeginAuth must never be accepted on another provider's callback. Each
// provider stores its session under its own key, so the comparison always runs
// against the issuing provider's AuthURL and can never cross-recognize a
// foreign state.
func Test_StateValidation_ProviderIsolation(t *testing.T) {
	a := assert.New(t)

	Store = NewProviderStore()
	res := httptest.NewRecorder()

	// Begin auth with faux, establishing state_REAL inside the faux session.
	reqFaux, err := http.NewRequest("GET", "/auth?provider=faux&state=state_REAL", nil)
	a.NoError(err)
	BeginAuthHandler(res, reqFaux)
	fauxSession, _ := Store.Get(reqFaux, SessionName)

	// A second provider's session holds a different state. The callback
	// targets faux but reuses the other provider's state value, which must not
	// be cross-recognized: validation reads state solely from the faux session.
	req, err := http.NewRequest("GET", "/auth/callback?provider=faux&state=state_OTHER", nil)
	a.NoError(err)
	session, _ := Store.New(req, SessionName)
	session.Values["faux"] = fauxSession.Values["faux"]
	a.NoError(session.Save(req, res))

	_, err = CompleteUserAuth(res, req)
	a.Error(err)
	a.Equal("state token mismatch", err.Error())

	// Conversely, the original provider's own state still passes, proving the
	// rejection came from the scope boundary rather than a broken session.
	req, _ = http.NewRequest("GET", "/auth/callback?provider=faux&state=state_REAL", nil)
	session, _ = Store.New(req, SessionName)
	session.Values["faux"] = fauxSession.Values["faux"]
	a.NoError(session.Save(req, res))
	_, err = CompleteUserAuth(res, req)
	a.NoError(err)
}

func Test_AppleStateValidation(t *testing.T) {
	a := assert.New(t)
	appleStateValue := "xyz123-#"
	form := url.Values{}
	form.Add("state", appleStateValue)
	req, _ := http.NewRequest(http.MethodPost, "/", strings.NewReader(form.Encode()))
	req.Form = form
	a.Equal(appleStateValue, GetState(req))
}

func gzipString(value string) string {
	var b bytes.Buffer
	gz := gzip.NewWriter(&b)
	if _, err := gz.Write([]byte(value)); err != nil {
		return "err"
	}
	if err := gz.Flush(); err != nil {
		return "err"
	}
	if err := gz.Close(); err != nil {
		return "err"
	}

	return b.String()
}

func ungzipString(value string) string {
	rdata := strings.NewReader(value)
	r, err := gzip.NewReader(rdata)
	if err != nil {
		return "err"
	}
	s, err := io.ReadAll(r)
	if err != nil {
		return "err"
	}

	return string(s)
}
