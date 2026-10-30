package admin

import "net/http"

// NewClientWith is NewClient with the authorities answered by rt.
func NewClientWith(cfg Config, rt http.RoundTripper) (*Client, error) {
	c, err := NewClient(cfg)
	if err != nil {
		return nil, err
	}
	c.http = func(Authority) *http.Client { return &http.Client{Transport: rt} }
	return c, nil
}
