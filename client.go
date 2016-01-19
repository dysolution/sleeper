package sleepwalker

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io/ioutil"
	"net/http"

	"github.com/Sirupsen/logrus"
	hashids "github.com/speps/go-hashids"
)

var pool *x509.CertPool
var log *logrus.Logger

// A RESTClient can perform operations against a REST API.
type RESTClient interface {
	Get(Findable) (Result, error)
	Create(Findable) (Result, error)
	Update(Findable) (Result, error)
	Delete(Findable) (Result, error)
}

type serializable interface {
	Marshal() ([]byte, error)
}

// Findable objects can report the URL where they can be found.
type Findable interface {
	Path() string
}

// A RESTObject has a canonical API endpoint URL and can be serialized to JSON.
type RESTObject interface {
	serializable
	Findable
}

// A Token is a string representation of an OAuth2 token.
type Token string

// getToken submits the provided credentials to the OAuth2 endpoint and
// returns a token that can be used to authenticate HTTP requests to the API.
func getToken(credentials *Credentials, oAuthEndpoint string) Token {
	desc := "getToken"
	if credentials.areInvalid() {
		log.Fatal("Not all required credentials were supplied.")
	}

	uri := oAuthEndpoint
	log.Debugf("%v: %s", desc, uri)
	values := formValues(credentials)
	log.Debugf("%v: %s", desc, values.Encode())

	resp, err := http.PostForm(uri, values)
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()

	payload, err := ioutil.ReadAll(resp.Body)
	log.Debugf("%v: %v", desc, resp.Status)
	log.Debugf("%v: %s", desc, payload)
	return tokenFrom(payload)
}

var clientIDs []string

// A Client uses an access token to submit HTTP requests to a REST API.
type Client struct {
	Credentials `json:"-"`
	Token       Token  `json:"-"`
	ID          string `json:"id"`
	APIRoot     string `json:"api_root"`
}

// GetClient returns a Client that can be used to send requests to a REST API.
func GetClient(key, secret, username, password, oAuthEndpoint, apiRoot string, logger *logrus.Logger) Client {
	creds := Credentials{
		APIKey:    key,
		APISecret: secret,
		Username:  username,
		Password:  password,
	}
	if logger != nil {
		log = logger
	}
	token := getToken(&creds, oAuthEndpoint)

	hd := hashids.NewData()
	hd.Salt = "farm to table salt"
	hd.MinLength = 8
	h := hashids.NewWithData(hd)
	id, _ := h.Encode([]int{45, 434, 1313, 99})

	return Client{creds, token, id, apiRoot}
}

// String implements fmt.Stringer.
func (c Client) String() string {
	return c.ID
}

// Create uses the provided metadata to create and object
// and returns it along with metadata about the HTTP request, including
// response time.
func (c Client) Create(object Findable) (Result, error) {
	return c.reqWithPayload("POST", object)
}

// Update uses the provided metadata to update an object and returns
// metadata about the HTTP request, including response time.
func (c Client) Update(object Findable) (Result, error) {
	return c.reqWithPayload("PUT", object)
}

// Delete destroys the object described by the provided object, as long as
// enough data is provided to unambiguously identify it to the API, and returns
// metadta about the HTTP request, including response time.
func (c Client) Delete(object Findable) (Result, error) {
	return c.req("DELETE", object.Path())
}

// Get uses the provided metadata to request an object from the API
// and returns it along with metadata about the HTTP request, including
// response time.
func (c Client) Get(object Findable) (Result, error) {
	return c.req("GET", object.Path())
}

// GetPath performs an HTTP GET against the provided path and returns metadata
// about the HTTP request, including response time.
func (c Client) GetPath(path string) (Result, error) {
	return c.req("GET", path)
}

func (c *Client) req(method, path string) (Result, error) {
	return c.performRequest(newRequest(method, path, c.Token, nil))
}

func (c *Client) reqWithPayload(method string, object Findable) (Result, error) {
	serializedObject, err := Marshal(object)
	if err != nil {
		return Result{}, err
	}
	request := newRequest(method, object.Path(), c.Token, serializedObject)
	return c.performRequest(request)
}

// insecureClient returns an HTTP client that will not verify the validity
// of an SSL certificate when performing a request.
func insecureClient() *http.Client {
	// pool = x509.NewCertPool()
	// pool.AppendCertsFromPEM(pemCerts)
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
		// RootCAs:            pool},
	}
	return &http.Client{Transport: tr}
}

// performRequest performs a request using the given parameters and
// returns a struct that contains the HTTP status code and payload from
// the server's response as well as metadata such as the response time.
func (c Client) performRequest(p request) (Result, error) {
	desc := "Client.performRequest"
	uri := c.APIRoot + p.Path

	if p.requiresAnObject() && p.Object != nil {
		log.WithFields(logrus.Fields{
			"object": p.Object,
		}).Debugf(desc)
	}
	req, err := http.NewRequest(p.Verb, uri, bytes.NewBuffer(p.Object))
	if err != nil {
		log.WithFields(logrus.Fields{
			"error":  err,
			"source": "http.NewRequest",
		}).Error(desc)
		return Result{}, err
	}
	p.httpRequest = req

	p.addHeaders(p.Token, c.APIKey)

	vr, err := doRequest(insecureClient(), req)
	if err != nil {
		log.WithFields(logrus.Fields{
			"error":  err,
			"source": "doRequest",
		}).Error(desc)
		return Result{}, err
	}
	result := Result{p, vr}

	logResult(desc, result)

	return result, nil
}

// logResult captures information that can help with analysis and
// troubleshooting and maps HTTP status classes to analagous log levels.
func logResult(desc string, result Result) {
	logEntry := log.WithFields(logrus.Fields{
		"method":        result.Verb,
		"path":          result.Path,
		"response_body": string(result.Payload),
	})
	switch {
	case result.StatusCode < 300:
		logEntry.Debug(desc)
	case result.StatusCode >= 300 && result.StatusCode <= 400:
		logEntry.Warn(desc)
	case result.StatusCode >= 400:
		logEntry.Error(desc)
	}
}

func tokenFrom(payload []byte) Token {
	var response map[string]string
	json.Unmarshal(payload, &response)
	return Token(response["access_token"])
}
