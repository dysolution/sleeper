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
var Log *logrus.Logger

type RESTClient interface {
	Get(Findable) (Result, error)
	Create(Findable) (Result, error)
	Update(Findable) (Result, error)
	Delete(Findable) (Result, error)
}

// Serializable objects can be Marshaled into JSON.
type Serializable interface {
	Marshal() ([]byte, error)
}

// Findable objects can report the URL where they can be found.
type Findable interface {
	Path() string
}

// A RESTObject has a canonical API endpoint URL and can be serialized to JSON.
type RESTObject interface {
	Serializable
	Findable
}

// A Token is a string representation of an OAuth2 token. It grants a user
// access to the ESP API for a limited time.
type Token string

// getToken submits the provided credentials to Getty's OAuth2 endpoint
// and returns a token that can be used to authenticate HTTP requests to the
// ESP API.
func getToken(credentials *Credentials, oAuthEndpoint string) Token {
	if credentials.AreInvalid() {
		Log.Fatal("Not all required credentials were supplied.")
	}

	uri := oAuthEndpoint
	Log.Debugf("%s", uri)
	formValues := FormValues(credentials)
	Log.Debugf("%s", formValues.Encode())

	resp, err := http.PostForm(uri, formValues)
	if err != nil {
		Log.Fatal(err)
	}
	defer resp.Body.Close()

	payload, err := ioutil.ReadAll(resp.Body)
	Log.Debugf("HTTP %d", resp.StatusCode)
	Log.Debugf("%s", payload)
	return tokenFrom(payload)
}

var clientIDs []string

// A Client is able to request an access token and submit HTTP requests to
// the ESP API.
type Client struct {
	Credentials `json:"-"`
	Token       Token  `json:"-"`
	ID          string `json:"id"`
}

// GetClient returns a Client that can be used to send requests to the ESP API.
func GetClient(key, secret, username, password, oAuthEndpoint, apiRoot string, logger *logrus.Logger) Client {
	creds := Credentials{
		APIKey:    key,
		APISecret: secret,
		Username:  username,
		Password:  password,
	}
	APIRoot = apiRoot
	if logger != nil {
		Log = logger
	}
	token := getToken(&creds, oAuthEndpoint)

	hd := hashids.NewData()
	hd.Salt = "farm to table salt"
	hd.MinLength = 8
	h := hashids.NewWithData(hd)
	id, _ := h.Encode([]int{45, 434, 1313, 99})

	return Client{creds, token, id}
}

// String implements fmt.Stringer.
func (c Client) String() string {
	return c.ID
}

// Create uses the provided metadata to create and object
// and returns it along with metadata about the HTTP request, including
// response time.
func (c Client) Create(object Findable) (Result, error) {
	desc := "Client.Create"
	result, err := c.post(object)
	if err != nil {
		Log.Errorf("%v: %v", desc, err)
		return Result{}, err
	}
	return result, nil
}

// Update uses the provided metadata to update an object and returns
// metadata about the HTTP request, including response time.
func (c Client) Update(object Findable) (Result, error) {
	desc := "Client.Update"
	result, err := c.put(object)
	if err != nil {
		Log.Errorf("%v: %v", desc, err)
		return Result{}, err
	}
	return result, nil
}

// VerboseDelete destroys the object described by the provided object,
// as long as enough data is provided to unambiguously identify it to the API.
func (c Client) Delete(object Findable) (Result, error) {
	desc := "Client.Delete"
	result, err := c._delete(object.Path())
	if err != nil {
		Log.WithFields(logrus.Fields{
			"error": err,
		}).Errorf("%v: %v", desc, err)
		return Result{}, err
	}
	return result, nil
}

// Get uses the provided metadata to request an object from the API
// and returns it along with metadata about the HTTP request, including
// response time.
func (c Client) Get(object Findable) (Result, error) {
	desc := "Client.Get"
	Log.Debugf("%v: given object: %v", desc, object)
	Log.Debugf("%v: attempting to get path: %v", desc, object.Path())
	result, err := c.get(object.Path())
	if err != nil {
		Log.WithFields(logrus.Fields{
			"error": err,
		}).Errorf("%v: %v", desc, err)
		return Result{}, err
	}
	return result, nil
}

func (c *Client) post(object Findable) (Result, error) {
	desc := "Client.post"
	serializedObject, err := Marshal(object)
	if err != nil {
		return Result{}, err
	}

	request := newRequest("POST", object.Path(), c.Token, serializedObject)
	result, err := c.performRequest(request)
	if err != nil {
		return Result{}, err
	}
	result.Log().Debug(desc)
	return result, nil
}

func (c *Client) put(object Findable) (Result, error) {
	desc := "Client.put"
	serializedObject, err := Marshal(object)
	if err != nil {
		Log.Errorf(desc+": %v", err)
		return Result{}, err
	}
	request := newRequest("PUT", object.Path(), c.Token, serializedObject)
	result, err := c.performRequest(request)
	if err != nil {
		Log.Errorf(desc+": %v", err)
		return Result{}, err
	}
	return result, nil
}

func (c *Client) _delete(path string) (Result, error) {
	desc := "Client._delete"
	result, err := c.performRequest(newRequest("DELETE", path, c.Token, nil))
	if err != nil {
		Log.Errorf(desc+": %v", err)
		return Result{}, err
	}
	return result, nil
}

func (c *Client) get(path string) (Result, error) {
	desc := "Client.get"
	result, err := c.performRequest(newRequest("GET", path, c.Token, nil))
	if err != nil {
		Log.Errorf(desc+": %v", err)
		return Result{}, err
	}
	return result, nil
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
	uri := APIRoot + p.Path

	if p.requiresAnObject() && p.Object != nil {
		Log.Debugf("Received serialized object: %s", p.Object)
	}
	req, err := http.NewRequest(p.Verb, uri, bytes.NewBuffer(p.Object))
	if err != nil {
		Log.WithFields(logrus.Fields{
			"error": err,
		}).Error(desc)
		return Result{}, err
	}
	p.httpRequest = req

	p.addHeaders(p.Token, c.APIKey)

	vr, err := getResult(insecureClient(), req)
	if err != nil {
		Log.Error(err)
		return Result{}, err
	}
	result := Result{p, vr}

	switch {
	case result.StatusCode < 300:
		Log.WithFields(logrus.Fields{
			"response_body": string(result.Payload),
		}).Debug(desc)
	case result.StatusCode >= 300 && result.StatusCode <= 400:
		Log.WithFields(logrus.Fields{
			"response_body": string(result.Payload),
		}).Warn(desc)
	case result.StatusCode >= 400:
		Log.WithFields(logrus.Fields{
			"response_body": string(result.Payload),
		}).Error(desc)
	}

	return result, nil
}

func tokenFrom(payload []byte) Token {
	var response map[string]string
	json.Unmarshal(payload, &response)
	return Token(response["access_token"])
}

// deprecated

func (c *Client) deprecatedGet(path string) []byte {
	request := newRequest("GET", path, c.Token, nil)
	result, err := c.performRequest(request)
	if err != nil {
		Log.Fatal(err)
	}
	result.Log().Debug("Client.get")
	Log.Debugf("%s\n", result.Payload)
	return result.Payload
}

func (c *Client) deprecatedPost(object RESTObject) []byte {
	serializedObject, err := Marshal(object)
	if err != nil {
		Log.Fatal(err)
	}
	request := newRequest("POST", object.Path(), c.Token, serializedObject)
	result, err := c.performRequest(request)
	if err != nil {
		Log.Fatal(err)
	}

	result.Log().Debug()
	Log.Debugf("%s\n", result.Payload)
	return result.Payload
}
