package kernel

import (
	"context"

	"io"
	"net"
	"net/http"

	"testing"
	"time"
)

func atomicClient(t *testing.T, socket string) *http.Client {
	t.Helper()
	tr := &http.Transport{}
	if socket != "" {
		tr.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", socket)
		}
	}
	t.Cleanup(tr.CloseIdleConnections)
	return &http.Client{Transport: tr, Timeout: 3 * time.Second}
}
func atomicRequest(t *testing.T, c *http.Client, url, method, secret string) (int, []byte) {
	t.Helper()
	r, e := http.NewRequest(method, url, nil)
	if e != nil {
		t.Fatal(e)
	}
	if secret != "" {
		r.Header.Set("Authorization", "Bearer "+secret)
	}
	res, e := c.Do(r)
	if e != nil {
		t.Fatal(e)
	}
	defer res.Body.Close()
	b, e := io.ReadAll(res.Body)
	if e != nil {
		t.Fatal(e)
	}
	return res.StatusCode, b
}
