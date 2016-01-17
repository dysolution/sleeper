package espsdk

import "net/url"

type Creds interface {
	APIKey()
	APISecret()
	Username()
	Password()
}

// Credentials represent a specific authorized application performing
// operations on objects belonging to a specific ESP user.
type credentials struct {
	APIKey    string
	APISecret string
	Username  string
	Password  string
}

func (c *credentials) areInvalid() bool {
	if len(c.APIKey) < 1 || len(c.APISecret) < 1 || len(c.Username) < 1 || len(c.Password) < 1 {
		return true
	}
	return false
}

func formValues(c *credentials) url.Values {
	v := url.Values{}
	v.Set("client_id", c.APIKey)
	v.Set("client_secret", c.APISecret)
	v.Set("username", c.Username)
	v.Set("password", c.Password)
	v.Set("grant_type", "password")
	return v
}
