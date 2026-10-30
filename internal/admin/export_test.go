package admin

import "net/http"

// ReadBackWait lets tests shorten the read-back after a change.
var ReadBackWait = &readBackWait

// NewClientRoutes is NewClient with each authority answered by its own
// RoundTripper, by URL.
func NewClientRoutes(cfg Config, rts map[string]http.RoundTripper) (*Client, error) {
	c, err := NewClient(cfg)
	if err != nil {
		return nil, err
	}
	c.http = func(a Authority) *http.Client { return &http.Client{Transport: rts[a.URL]} }
	return c, nil
}
