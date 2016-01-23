package sleepwalker

import (
	"errors"
	"io/ioutil"
	"net/http"
	"time"
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
	if err != nil {
		if resp != nil {
			code := resp.StatusCode
			status := resp.Status
			resp.Body.Close()
			return response{code, status, nil, duration, 0}, err
		} else {
			return response{}, errors.New("nil response")
		}
	}
	return analyzeResponse(resp, duration)
}

func timeResponse(c *http.Client, req *http.Request) (*http.Response, time.Duration, error) {
	desc := "timeRequest"
	start := time.Now()
	resp, err := c.Do(req)
	duration := time.Since(start) / time.Millisecond
	if err != nil {
		log.WithFields(map[string]interface{}{
			"error": err,
		}).Error(desc)
	}
	return resp, duration, err
}

func analyzeResponse(resp *http.Response, duration time.Duration) (response, error) {
	desc := "getResponse"
	payload, err := ioutil.ReadAll(resp.Body)
	response := response{resp.StatusCode, resp.Status, payload, duration, len(payload)}
	resp.Body.Close()

	if err != nil {
		log.WithFields(map[string]interface{}{
			"error": err,
		}).Error(desc + " (from ioutil.ReadAll)")
		return response, err
	}
	return response, nil
}
