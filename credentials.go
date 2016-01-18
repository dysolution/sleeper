package sleepwalker

import "net/url"

type Creds interface {
	APIKey()
	APISecret()
	Username()
	Password()
}

// Credentials represent a specific authorized application performing
// operations on objects belonging to a specific ESP user.
type Credentials struct {
	APIKey    string `json:"api_key"`
	APISecret string `json:"-"`
	Username  string `json:"username"`
	Password  string `json:"-"`
}

func (c *Credentials) AreInvalid() bool {
	if len(c.APIKey) < 1 || len(c.APISecret) < 1 || len(c.Username) < 1 || len(c.Password) < 1 {
		return true
	}
	return false
}

func FormValues(c *Credentials) url.Values {
	v := url.Values{}
	v.Set("client_id", c.APIKey)
	v.Set("client_secret", c.APISecret)
	v.Set("username", c.Username)
	v.Set("password", c.Password)
	v.Set("grant_type", "password")
	return v
}
