package sleepwalker

import (
	"encoding/json"
	"time"

	"github.com/Sirupsen/logrus"
)

// A Result provides an overview of a completed API request and
// its result, including timing and HTTP status codes.
type Result struct {
	request
	response
}

// Marshal serializes a FulfilledRequest into a byte stream.
func (r *Result) Marshal() ([]byte, error) {
	return json.Marshal(r)
}

// MarshalIndent serializes a FulfilledRequest into indented JSON.
func (r *Result) MarshalIndent() ([]byte, error) {
	return json.MarshalIndent(r, "", "    ")
}

// ResponseTime reflects the time elapsed while waiting for the response after
// sending an HTTP request.
func (r *Result) ResponseTime() *time.Duration {
	return &r.Duration
}

// Stats returns fields that logrus can parse.
func (r *Result) stats() logrus.Fields {
	return logrus.Fields{
		"method":        r.Verb,
		"path":          r.Path,
		"response_time": r.Duration * time.Millisecond,
		"response_size": r.Size,
		"status_code":   r.StatusCode,
	}
}

// Log provides a convenient way to output information about an HTTP request
// the user is likely to want.
func (r *Result) Log() *logrus.Entry {
	return log.WithFields(r.stats())
}

// LogBrief logs only an HTTP request's status code and response time.
func (r *Result) LogBrief() *logrus.Entry {
	return log.WithFields(logrus.Fields{
		"response_time": r.Duration * time.Millisecond,
		"status_code":   r.StatusCode,
	})
}
