// Package slack implements the OAuth2 protocol for authenticating users through slack.
// This package can be used as a reference implementation of an OAuth2 provider for Goth.
package slack

import (
	"bytes"
	"encoding/json"
	"io"
	"io/ioutil"
	"net/http"
	"strings"

	"fmt"

	"github.com/markbates/goth"
	"golang.org/x/oauth2"
)

// Scopes
const (
	ScopeOpenID  string = "openid"
	ScopeProfile string = "profile"
)

// URLs and endpoints
const (
	authURL         string = "https://slack.com/openid/connect/authorize"
	tokenURL        string = "https://slack.com/api/openid.connect.token"
	endpointProfile string = "https://slack.com/api/openid.connect.userInfo"
)

// Provider is the implementation of `goth.Provider` for accessing Slack.
type Provider struct {
	ClientKey            string
	Secret               string
	CallbackURL          string
	HTTPClient           *http.Client
	config               *oauth2.Config
	providerName         string
	tokenRotationEnabled bool
}

// New creates a new Slack provider and sets up important connection details.
// You should always call `slack.New` to get a new provider.  Never try to
// create one manually.
func New(clientKey, secret, callbackURL string, tokenRotationEnabled bool, scopes ...string) *Provider {
	p := &Provider{
		ClientKey:            clientKey,
		Secret:               secret,
		CallbackURL:          callbackURL,
		tokenRotationEnabled: tokenRotationEnabled,
		providerName:         "slack",
	}
	p.config = newConfig(p, scopes)
	return p
}

// Name is the name used to retrieve this provider later.
func (p *Provider) Name() string {
	return p.providerName
}

// SetName is to update the name of the provider (needed in case of multiple providers of 1 type)
func (p *Provider) SetName(name string) {
	p.providerName = name
}

// Client returns the http.Client used in the provider.
func (p *Provider) Client() *http.Client {
	return goth.HTTPClientWithFallBack(p.HTTPClient)
}

// Debug is a no-op for the slack package.
func (p *Provider) Debug(debug bool) {}

// BeginAuth asks Slack for an authentication end-point.
func (p *Provider) BeginAuth(state string) (goth.Session, error) {
	return &Session{
		AuthURL: p.config.AuthCodeURL(state),
	}, nil
}

// FetchUser will go to Slack and access basic information about the user.
func (p *Provider) FetchUser(session goth.Session) (goth.User, error) {
	sess := session.(*Session)
	user := goth.User{
		AccessToken:  sess.AccessToken,
		Provider:     p.Name(),
		RefreshToken: sess.RefreshToken,
		ExpiresAt:    sess.ExpiresAt,
	}

	if user.AccessToken == "" {
		// data is not yet retrieved since accessToken is still empty
		return user, fmt.Errorf("%s cannot get user information without accessToken", p.providerName)
	}

	req, err := http.NewRequest(http.MethodPost, endpointProfile, nil)
	if err != nil {
		return user, err
	}

	req.Header.Add("Authorization", "Bearer "+sess.AccessToken)
	response, err := p.Client().Do(req)
	if err != nil {
		return user, err
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return user, fmt.Errorf("%s responded with a %d trying to fetch user information", p.providerName, response.StatusCode)
	}

	bits, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return user, err
	}

	err = json.NewDecoder(bytes.NewReader(bits)).Decode(&user.RawData)
	if err != nil {
		return user, err
	}

	err = userFromReader(bytes.NewReader(bits), &user)

	return user, err
}

func newConfig(provider *Provider, scopes []string) *oauth2.Config {
	c := &oauth2.Config{
		ClientID:     provider.ClientKey,
		ClientSecret: provider.Secret,
		RedirectURL:  provider.CallbackURL,
		Endpoint: oauth2.Endpoint{
			AuthURL:  authURL,
			TokenURL: tokenURL,
		},
		Scopes: []string{},
	}

	if len(scopes) > 0 {
		for _, scope := range scopes {
			c.Scopes = append(c.Scopes, scope)
		}
	} else {
		c.Scopes = append(c.Scopes, ScopeOpenID)
	}
	return c
}

func userFromReader(r io.Reader, user *goth.User) error {
	u := struct {
		NickName  string `json:"name"`
		UserID    string `json:"https://slack.com/user_id"`
		Email     string `json:"email"`
		AvatarURL string `json:"https://slack.com/user_image_32"`
		FirstName string `json:"given_name"`
		LastName  string `json:"family_name"`
	}{}
	err := json.NewDecoder(r).Decode(&u)
	if err != nil {
		return err
	}
	user.Email = u.Email
	user.Name = strings.TrimSpace(u.FirstName + " " + u.LastName)
	user.NickName = u.NickName
	user.UserID = u.UserID
	user.AvatarURL = u.AvatarURL
	user.FirstName = u.FirstName
	user.LastName = u.LastName

	return nil
}

//RefreshTokenAvailable refresh token is provided by auth provider or not
func (p *Provider) RefreshTokenAvailable() bool {
	return p.tokenRotationEnabled
}

//RefreshToken get new access token based on the refresh token
func (p *Provider) RefreshToken(refreshToken string) (*oauth2.Token, error) {
	token := &oauth2.Token{RefreshToken: refreshToken}
	ts := p.config.TokenSource(goth.ContextForClient(p.Client()), token)
	newToken, err := ts.Token()
	if err != nil {
		return nil, err
	}
	return newToken, err
}
