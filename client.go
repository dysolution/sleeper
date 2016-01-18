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

// A Token is a string representation of an OAuth2 token.
type Token string

// getToken submits the provided credentials to the OAuth2 endpoint and
// returns a token that can be used to authenticate HTTP requests to the API.
func getToken(credentials *Credentials, oAuthEndpoint string) Token {
	desc := "getToken"
	if credentials.AreInvalid() {
		Log.Fatal("Not all required credentials were supplied.")
	}

	uri := oAuthEndpoint
	Log.Debugf("%v: %s", desc, uri)
	formValues := FormValues(credentials)
	Log.Debugf("%v: %s", desc, formValues.Encode())

	resp, err := http.PostForm(uri, formValues)
	if err != nil {
		Log.Fatal(err)
	}
	defer resp.Body.Close()

	payload, err := ioutil.ReadAll(resp.Body)
	Log.Debugf("%v: %v", desc, resp.Status)
	Log.Debugf("%v: %s", desc, payload)
	return tokenFrom(payload)
}

var clientIDs []string

// A Client uses an access token to submit HTTP requests to a REST API.
type Client struct {
	Credentials `json:"-"`
	Token       Token  `json:"-"`
	ID          string `json:"id"`
}

// GetClient returns a Client that can be used to send requests to a REST API.
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
	result, err := c.reqWithPayload("POST", object)
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
	result, err := c.reqWithPayload("PUT", object)
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
	result, err := c.req("DELETE", object.Path())
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
	Log.WithFields(logrus.Fields{
		"path":   object.Path(),
		"object": object,
	}).Debugf("Client.Get")
	return c.req("GET", object.Path())
}

// GetPath performs an HTTP GET against the provided path and returns metadata
// about the HTTP request, including response time.
func (c Client) GetPath(path string) (Result, error) {
	Log.WithFields(logrus.Fields{
		"path": path,
	}).Debugf("Client.GetPath")
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
	uri := APIRoot + p.Path

	if p.requiresAnObject() && p.Object != nil {
		Log.Debugf("Received serialized object: %s", p.Object)
	}
	req, err := http.NewRequest(p.Verb, uri, bytes.NewBuffer(p.Object))
	if err != nil {
		Log.WithFields(logrus.Fields{
			"error": err,
		}).Error(desc + " (from http.NewRequest)")
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

	logResult(desc, result)

	return result, nil
}

// logResult captures information that can help with analysis and
// troubleshooting and maps HTTP status classes to analagous log levels.
func logResult(desc string, result Result) {
	logEntry := Log.WithFields(logrus.Fields{
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
