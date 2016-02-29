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
func (r *Result) stats() map[string]interface{} {
	return map[string]interface{}{
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
	return Log.WithFields(r.stats())
}

// LogBrief logs only an HTTP request's status code and response time.
func (r *Result) LogBrief() *logrus.Entry {
	return Log.WithFields(map[string]interface{}{
		"response_time": r.Duration * time.Millisecond,
		"status_code":   r.StatusCode,
	})
}

// LogPayload includes the HTTP response payload.
func (r *Result) LogPayload() *logrus.Entry {
	fields := r.stats()
	var payload interface{}
	json.Unmarshal(r.Payload, &payload)
	fields["payload"] = payload
	return Log.WithFields(fields)
}

// Report captures information that can help with analysis and
// troubleshooting and maps HTTP status classes to analagous log levels.
func (r *Result) Report(desc string) {
	switch {
	case r.StatusCode < 300:
		r.Log().Debug(desc)
	case r.StatusCode >= 300 && r.StatusCode <= 400:
		r.Log().Warn(desc)
	case r.StatusCode >= 400:
		r.Log().Error(desc)
	}
}
