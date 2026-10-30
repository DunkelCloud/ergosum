package e2e

import (
	"bufio"
	"crypto/tls"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/DunkelCloud/ergosum/internal/tlspin"
)

// TestAnnouncedBodyNeverSent: a request that announces a body it never
// sends is answered at once instead of holding the connection, on the API
// listener for GET and for a body above the limit.
func TestAnnouncedBodyNeverSent(t *testing.T) {
	e := newEnv(t, envOptions{})
	addr := strings.TrimPrefix(e.url, "https://")
	for _, head := range []string{
		"GET /v1/keys HTTP/1.1\r\nHost: x\r\nContent-Length: 200000\r\n\r\n",
		"GET /nowhere HTTP/1.1\r\nHost: x\r\nContent-Length: 200000\r\n\r\n",
		"POST /v1/bindings HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: 300000\r\n\r\n",
	} {
		conn, err := tls.Dial("tcp", addr, tlspin.ClientConfig(nil, tlspin.Fingerprints(e.fingerprint())))
		if err != nil {
			t.Fatal(err)
		}
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		if _, err := conn.Write([]byte(head)); err != nil {
			t.Fatal(err)
		}
		resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
		if err != nil {
			t.Fatalf("%q: no answer: %v", strings.SplitN(head, "\r\n", 2)[0], err)
		}
		_ = resp.Body.Close()
		_ = conn.Close()
		if resp.StatusCode != http.StatusRequestEntityTooLarge || !resp.Close {
			t.Fatalf("%q: status %d, close %v", strings.SplitN(head, "\r\n", 2)[0], resp.StatusCode, resp.Close)
		}
	}
}
