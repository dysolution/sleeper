package sleepwalker

import (
	"io/ioutil"
	"net/http"
	"time"

	"github.com/Sirupsen/logrus"
)

// A response contains information relative to a completed request,
// including the time elapsed to fulfill the request and any errors.
type response struct {
	StatusCode int           `json:"status_code"`
	Status     string        `json:"status"`
	Payload    []byte        `json:"-"`
	Duration   time.Duration `json:"response_time"`
	Size       int           `json:"response_size"`
}

func doRequest(c *http.Client, req *http.Request) (response, error) {
	resp, duration, err := timeResponse(c, req)
	defer resp.Body.Close()
	if err != nil {
		return response{resp.StatusCode, resp.Status, nil, duration, 0}, err
	}
	return analyzeResponse(resp, duration)
}

func timeResponse(c *http.Client, req *http.Request) (*http.Response, time.Duration, error) {
	desc := "timeRequest"
	start := time.Now()
	resp, err := c.Do(req)
	duration := time.Since(start) / time.Millisecond
	if err != nil {
		Log.WithFields(logrus.Fields{
			"error": err,
		}).Error(desc + " (from http.Client.Do)")
	}
	return resp, duration, err
}

func analyzeResponse(resp *http.Response, duration time.Duration) (response, error) {
	desc := "getResponse"
	payload, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		Log.WithFields(logrus.Fields{
			"error": err,
		}).Error(desc + " (from ioutil.ReadAll)")
		return response{resp.StatusCode, resp.Status, payload, duration, len(payload)}, err
	}
	return response{resp.StatusCode, resp.Status, payload, duration, len(payload)}, nil
}
