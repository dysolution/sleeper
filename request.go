package sleepwalker

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
)

// A Request represents the specific API endpoint and action to take. The
// Object is optional and applies only to endpoints that create or update
// items (POST and PUT).
type request struct {
	Verb        string `json:"method"`
	Path        string `json:"path"`
	RelPath     string `json:"rel_path"`
	Token       Token  `json:"-"`
	Object      []byte `json:"object"`
	httpRequest *http.Request
}

func newRequest(verb, path string, token Token, object []byte) (request, error) {
	req, err := http.NewRequest(verb, path, bytes.NewBuffer(object))
	if err != nil {
		return request{}, errors.New("http.NewRequest failed")
	}
	return request{
		Verb:        verb,
		Path:        path,
		Token:       token,
		Object:      object,
		httpRequest: req,
	}, nil
}

func (r *request) requiresAnObject() bool {
	if r.Verb == "POST" || r.Verb == "PUT" || r.Verb == "DELETE" {
		return true
	}
	return false
}

func (rqst *request) handleObject() {
	if rqst.requiresAnObject() && rqst.Object != nil {
		var obj interface{}
		json.Unmarshal(rqst.Object, &obj)
		Log.WithFields(map[string]interface{}{
			"method": rqst.Verb,
			"path":   rqst.Path,
			"object": obj,
		}).Debugf("Client.performRequest")
	}
}

func (p *request) addHeaders(token Token, apiKey string) {
	p.httpRequest.Header.Set("Authorization", "Token token="+string(token))
	p.httpRequest.Header.Set("Content-Type", "application/json")
	p.httpRequest.Header.Set("Api-Key", apiKey)
}

// Marshal serializes an object into a byte slice.
func Marshal(object interface{}) ([]byte, error) {
	bytes, err := json.MarshalIndent(object, "", "\t")
	if err != nil {
		Log.WithFields(map[string]interface{}{
			"error": err,
		}).Error("sleepwalker.Marshal")
		return nil, err
	}
	return bytes, nil
}

// Unmarshal attempts to deserialize the provided JSON payload
// into an object.
func Unmarshal(payload []byte) interface{} {
	var dest interface{}
	err := json.Unmarshal(payload, &dest)
	if err != nil {
		Log.WithFields(map[string]interface{}{
			"error": err,
		}).Error("sleepwalker.Unmarshal")
	}
	return dest
}
