package sleepwalker

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io/ioutil"
	"math/rand"
	"net/http"

	"github.com/Sirupsen/logrus"
)

var pool *x509.CertPool
var Log *logrus.Logger

var transport *http.Transport // avoid leaks

// A RESTClient can perform operations against a REST API.
type RESTClient interface {
	Get(Findable) (Result, error)
	Create(Findable) (Result, error)
	Update(Findable) (Result, error)
	Delete(Findable) (Result, error)
	Put(Findable, string) (Result, error)
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
		Log.Fatal("Not all required credentials were supplied.")
	}

	uri := oAuthEndpoint
	Log.WithFields(map[string]interface{}{
		"path": uri,
	}).Debug(desc)

	values := formValues(credentials)
	Log.WithFields(map[string]interface{}{
		"values": values.Encode(),
	}).Debug(desc)

	resp, err := http.PostForm(uri, values)
	if err != nil {
		Log.Fatal(err)
	}
	defer resp.Body.Close()

	payload, err := ioutil.ReadAll(resp.Body)
	Log.WithFields(map[string]interface{}{
		"status":  resp.Status,
		"payload": string(payload),
	}).Debug(desc)
	return tokenFrom(payload)
}

var clientIDs []string

// A Client uses an access token to submit HTTP requests to a REST API.
type Client struct {
	*Credentials `json:"-"`
	Token        Token  `json:"-"`
	ID           string `json:"id"`
	APIRoot      string `json:"api_root"`
}

func randHex(n int) string {
	var letters = []rune("0123456789abcdef")
	b := make([]rune, n)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

// GetClient returns a Client that can be used to send requests to a REST API.
func GetClient(cfg *Config) *Client {
	if cfg.Logger != nil {
		Log = cfg.Logger
	}
	token := getToken(cfg.Credentials, cfg.OAuthEndpoint)
	id := randHex(4)
	return &Client{cfg.Credentials, token, id, cfg.APIRoot}
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

// Put uses the provided metadata to perform an HTTP PUT against the provided
// path and returns metadata about the HTTP request, including response time.
func (c Client) Put(object Findable, path string) (Result, error) {
	return c.reqWithPayloadAndPath("PUT", object, path)
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
	req, _ := newRequest(method, c.APIRoot+path, c.Token, nil)
	return c.performRequest(req)
}

func (c *Client) reqWithPayload(method string, object Findable) (Result, error) {
	serializedObject, err := Marshal(object)
	if err != nil {
		return Result{}, err
	}
	request, _ := newRequest(method, c.APIRoot+object.Path(), c.Token, serializedObject)
	return c.performRequest(request)
}

func (c *Client) reqWithPayloadAndPath(method string, object Findable, path string) (Result, error) {
	serializedObject, err := Marshal(object)
	if err != nil {
		return Result{}, err
	}
	request, _ := newRequest(method, c.APIRoot+path, c.Token, serializedObject)
	return c.performRequest(request)
}

// performRequest performs a request using the given parameters and
// returns a struct that contains the HTTP status code and payload from
// the server's response as well as metadata such as the response time.
func (c Client) performRequest(req request) (Result, error) {
	desc := "Client.performRequest"

	req.handleObject()
	req.addHeaders(req.Token, c.APIKey)

	resp, err := doRequest(&http.Client{
		Transport: insecureTransport()},
		req.httpRequest,
	)
	if err != nil {
		Log.WithFields(map[string]interface{}{
			"error":  err,
			"source": "doRequest",
		}).Error()
		return Result{}, err
	}

	result := Result{req, resp}
	result.Report(desc)
	return result, nil
}

// insecureTransport avoids leaks by memoizing a single transport.
func insecureTransport() *http.Transport {
	if transport == nil {
		transport = &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		}
	}
	return transport
}

func tokenFrom(payload []byte) Token {
	var response map[string]string
	json.Unmarshal(payload, &response)
	return Token(response["access_token"])
}
