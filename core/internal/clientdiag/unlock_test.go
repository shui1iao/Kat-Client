package clientdiag

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
)

func TestOfflineHTTPFixtures(t *testing.T) {
	b, e := os.ReadFile("testdata/unlock.json")
	if e != nil {
		t.Fatal(e)
	}
	var cases []struct {
		Service, Want, Evidence string
		Pages                   []struct {
			URL, Body, Location, Method string
			Status                      int
		}
	}
	if json.Unmarshal(b, &cases) != nil {
		t.Fatal("invalid fixtures")
	}
	for _, c := range cases {
		t.Run(c.Service+"/"+c.Want+"/"+c.Evidence, func(t *testing.T) {
			i := 0
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if i >= len(c.Pages) {
					t.Error("unexpected request")
					w.WriteHeader(500)
					return
				}
				p := c.Pages[i]
				i++
				u, _ := url.Parse(p.URL)
				if r.Method != p.Method || r.URL.RequestURI() != u.RequestURI() {
					t.Error(r.Method, r.URL)
				}
				if r.Header.Get("Cookie") != "" || r.Header.Get("Authorization") != "" {
					t.Error("credentials sent")
				}
				w.Header().Set("Location", p.Location)
				w.WriteHeader(p.Status)
				io.WriteString(w, p.Body)
			}))
			defer s.Close()
			client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
			fetch := func(ctx context.Context, m, u string) (Page, error) {
				orig, _ := url.Parse(u)
				r, _ := http.NewRequestWithContext(ctx, m, s.URL+orig.RequestURI(), nil)
				resp, e := client.Do(r)
				if e != nil {
					return Page{}, e
				}
				defer resp.Body.Close()
				b, e := io.ReadAll(resp.Body)
				return Page{Status: resp.StatusCode, Body: string(b), URL: u, Location: resp.Header.Get("Location")}, e
			}
			v := Detect(context.Background(), c.Service, fetch)
			if v.HTTPStatus != c.Pages[len(c.Pages)-1].Status {
				t.Fatalf("lost terminal HTTP: %+v", v)
			}
			if v.Result != c.Want {
				t.Fatalf("want %s got %+v", c.Want, v)
			}
			if i != len(c.Pages) {
				t.Fatalf("requests %d != %d", i, len(c.Pages))
			}
		})
	}
}
func TestRedirectAndURLBoundaries(t *testing.T) {
	for _, u := range []string{"http://a/", "https://a/#token", "https://u:p@a/", "https:///x", "https://a/\n"} {
		if ValidURL(u) {
			t.Fatal(u)
		}
	}
	base, _ := http.NewRequest("GET", "https://a.example/start", nil)
	for _, u := range []string{"http://a.example/", "https://b.example/", "https://a.example.evil/"} {
		r, _ := http.NewRequest("GET", u, nil)
		if Redirect(r, []*http.Request{base}) != http.ErrUseLastResponse {
			t.Fatal(u)
		}
	}
	r, _ := http.NewRequest("GET", "https://a.example/next", nil)
	r.Header.Set("Cookie", "fixture")
	if Redirect(r, []*http.Request{base}) != nil || r.Header.Get("Cookie") != "" {
		t.Fatal("same-host/no-cookie")
	}
}
func TestCancellationFailsNotUnlocked(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
	defer cancel()
	v := Detect(ctx, "ChatGPT", func(ctx context.Context, _, _ string) (Page, error) { <-ctx.Done(); return Page{}, ctx.Err() })
	if v.Result != "failed" {
		t.Fatal(v)
	}
}

func TestPageBundleCaptchaFlagsAreNotAChallenge(t *testing.T) {
	p := Page{Status: 200, Body: `<html><script>{"captchaEnabled":true,"recaptchaKey":"public"}</script><h1>Gemini is not available in your region</h1></html>`}
	v := Detect(context.Background(), "Gemini", func(context.Context, string, string) (Page, error) { return p, nil })
	if v.Result != "blocked" {
		t.Fatal(v)
	}
}

// Error strings, DNS names and URLs below are poison sentinels, not real secrets.
func TestAnonymousFailureChainSafeAndStaged(t *testing.T) {
	for _, c := range []struct {
		name string
		err  error
		code string
	}{
		{"dns", &net.DNSError{Name: "PRIVATE_SENTINEL", Err: "PRIVATE_SENTINEL"}, "[dns]"},
		{"socks", &net.OpError{Op: "dial", Net: "tcp", Err: errors.New("PRIVATE_SENTINEL")}, "[connection]"},
		{"certificate", x509.UnknownAuthorityError{}, "[tls]"},
		{"tls_record", tls.RecordHeaderError{}, "[tls]"},
		{"deadline", context.DeadlineExceeded, "[timeout]"},
		{"header_timeout", fixtureTimeout{}, "[timeout]"},
		{"body_eof", io.ErrUnexpectedEOF, "[io]"},
		{"cancel", context.Canceled, "[canceled]"},
		{"body_limit", ErrBodyLimit, "[body_limit]"},
		{"unknown", errors.New("https://private.invalid/?token=PRIVATE_SENTINEL"), "[request]"},
	} {
		t.Run(c.name, func(t *testing.T) {
			err := &url.Error{Op: "Get", URL: "https://private.invalid/?token=PRIVATE_SENTINEL", Err: c.err}
			v := Detect(context.Background(), "Netflix", func(context.Context, string, string) (Page, error) { return Page{Status: 200}, err })
			if v.Result != "failed" || v.HTTPStatus != 200 || !strings.Contains(v.Reason, c.code) || !strings.Contains(v.Reason, "Netflix 匿名地区元数据") || strings.Contains(v.Reason, "PRIVATE_SENTINEL") || strings.Contains(v.Reason, "https:") {
				t.Fatalf("unsafe/lost cause: %+v", v)
			}
			if c.name == "socks" && strings.Contains(v.Reason, "[dns]") {
				t.Fatal("guessed remote DNS")
			}
		})
	}
}

type fixtureTimeout struct{}

func (fixtureTimeout) Error() string   { return "PRIVATE_SENTINEL" }
func (fixtureTimeout) Timeout() bool   { return true }
func (fixtureTimeout) Temporary() bool { return true }

func TestAnonymousChallengeAlwaysPrecedesMetadata(t *testing.T) {
	for _, name := range Services {
		t.Run(name, func(t *testing.T) {
			v := Detect(context.Background(), name, func(context.Context, string, string) (Page, error) {
				return Page{Status: 200, Body: `<title>Just a moment</title>cf-chl-check <script>netflix.reactContext = {"models":{"geo":{"data":{"requestCountry":{"id":"HK","status":"ALLOW"}}},"nmTitleGQL":{"data":{"metaData":{"videoId":80057281,"isOriginal":true,"isAvailable":true}}}}};</script>`}, nil
			})
			if v.Result != "challenge" || !strings.Contains(v.Reason, "[challenge]") || v.HTTPStatus != 200 {
				t.Fatal(v)
			}
		})
	}
}
func TestAnonymousNoCountryOnlyPositiveOrUnsafeRedirect(t *testing.T) {
	for _, name := range Services {
		v := Detect(context.Background(), name, func(context.Context, string, string) (Page, error) {
			return Page{Status: 200, Body: `{"country_code":"US","region":"JP","GL":"JP"}`}, nil
		})
		if v.Result != "unknown" {
			t.Fatal(name, v)
		}
	}
	for _, target := range []string{"https://gemini.google.com.evil/app-unavailable-in-region", "http://gemini.google.com/app-unavailable-in-region", "https://u:p@gemini.google.com/app-unavailable-in-region", "https://gemini.google.com/not-app-unavailable-in-region"} {
		if regionRedirect(Page{Status: 302, Location: target}, "gemini.google.com") {
			t.Fatal("unsafe negative", target)
		}
	}
	if !regionRedirect(Page{Status: 200, URL: "https://www.disneyplus.com/welcome/unavailable"}, "disneyplus.com") {
		t.Fatal("lost same-host final unavailable page")
	}
}
func TestAnonymousAuxiliaryTraceCannotHideHTTPOrChallenge(t *testing.T) {
	for _, service := range []string{"ChatGPT"} {
		for _, trace := range []Page{{Status: 403, Body: "ip=203.0.113.9\nloc=SG\n"}, {Status: 200, Body: "cf-chl-check\nip=203.0.113.9\nloc=SG\n"}} {
			calls := 0
			v := Detect(context.Background(), service, func(context.Context, string, string) (Page, error) {
				calls++
				if calls == 1 {
					return Page{Status: 200, Body: `{"requires_cookie_consent":false}`}, nil
				}
				return trace, nil
			})
			want := "unknown"
			if trace.Status == 200 {
				want = "challenge"
			}
			if v.Result != want || calls != 2 || v.HTTPStatus != trace.Status || (!strings.Contains(v.Reason, "[http]") && !strings.Contains(v.Reason, "[challenge]")) {
				t.Fatal(service, v, calls)
			}
		}
	}
}

func TestAnonymousHTTPRejectionCannotBecomePositive(t *testing.T) {
	for _, name := range Services {
		for _, status := range []int{401, 403, 451, 500} {
			v := Detect(context.Background(), name, func(context.Context, string, string) (Page, error) {
				return Page{Status: status, Body: `{"country_code":"US","region":"JP","GL":"JP","error":{"code":"unknown"}}`}, nil
			})
			if v.Result != "unknown" || v.HTTPStatus != status || !strings.Contains(v.Reason, "[http]") {
				t.Fatal(name, status, v)
			}
		}
	}
}

func TestAnonymousSupportedPositivesAndGeminiEvidenceBoundary(t *testing.T) {
	b, e := os.ReadFile("testdata/unlock.json")
	if e != nil {
		t.Fatal(e)
	}
	var cases []struct {
		Service, Want string
		Pages         []struct {
			URL, Body, Location, Method string
			Status                      int
		}
	}
	if e = json.Unmarshal(b, &cases); e != nil {
		t.Fatal(e)
	}
	positive := map[string]bool{}
	for _, c := range cases {
		if c.Want != "unlocked" {
			continue
		}
		t.Run(c.Service, func(t *testing.T) {
			calls := 0
			v := Detect(context.Background(), c.Service, func(ctx context.Context, m, u string) (Page, error) {
				if calls >= len(c.Pages) {
					t.Fatal("unexpected request")
				}
				p := c.Pages[calls]
				calls++
				if m != p.Method || u != p.URL {
					t.Fatal("wrong request path", m, u)
				}
				return Page{Status: p.Status, Body: p.Body, URL: p.URL, Location: p.Location}, nil
			})
			if v.Result != "unlocked" || !strings.Contains(v.Reason, "[anonymous]") || v.Region == "" || calls != len(c.Pages) {
				t.Fatal("positive is not executable", v, calls)
			}
			positive[c.Service] = true
		})
	}
	for _, name := range Services {
		if name == "Gemini" {
			if positive[name] {
				t.Fatal("Gemini has no verified anonymous positive schema")
			}
			continue
		}
		if !positive[name] {
			t.Fatal("existing service lost its reachable positive", name)
		}
	}
}
func TestAnonymousPositiveChallengeAndRejectionStillWin(t *testing.T) {
	b, e := os.ReadFile("testdata/unlock.json")
	if e != nil {
		t.Fatal(e)
	}
	var cases []struct {
		Service, Want string
		Pages         []struct {
			URL, Body, Location string
			Status              int
		}
	}
	if e = json.Unmarshal(b, &cases); e != nil {
		t.Fatal(e)
	}
	for _, c := range cases {
		if c.Want != "unlocked" {
			continue
		}
		for _, status := range []int{200, 403} {
			calls := 0
			v := Detect(context.Background(), c.Service, func(context.Context, string, string) (Page, error) {
				p := c.Pages[calls]
				calls++
				return Page{Status: status, Body: "<title>Just a moment</title>cf-chl-check" + p.Body, URL: p.URL}, nil
			})
			if v.Result != "challenge" || !strings.Contains(v.Reason, "[challenge]") || calls != 1 {
				t.Fatal("positive overrode challenge", c.Service, v, calls)
			}
		}
	}
}

// These fragments test classification and safe reasons only. They are not
// evidence that a public exit currently receives an accepted positive schema.
func TestAnonymousPreciseUnknownReasons(t *testing.T) {
	for _, c := range []struct{ name, body, code, detail string }{
		{"ChatGPT", `{}`, "[policy]", "缺少"},
		{"ChatGPT", `{"error":{"code":"PRIVATE_SENTINEL"},"requires_cookie_consent":false}`, "[policy_error]", "错误结构"},
		{"ChatGPT", `{"requires_cookie_consent":"PRIVATE_SENTINEL"}`, "[policy]", "布尔值"},
		{"Gemini", `<h1>About</h1>PRIVATE_SENTINEL`, "[anonymous_evidence]", "证据"},
	} {
		t.Run(c.name+"/"+c.code+"/"+c.detail, func(t *testing.T) {
			calls := 0
			v := Detect(context.Background(), c.name, func(context.Context, string, string) (Page, error) {
				calls++
				return Page{Status: 200, Body: c.body, URL: "https://official.invalid/?token=PRIVATE_SENTINEL"}, nil
			})
			if v.Result != "unknown" || v.HTTPStatus != 200 || calls != 1 || !strings.Contains(v.Reason, c.code) || !strings.Contains(v.Reason, c.detail) || strings.Contains(v.Reason, "PRIVATE_SENTINEL") || strings.Contains(v.Reason, "https:") {
				t.Fatalf("wrong classification or unsafe reason: %+v calls=%d", v, calls)
			}
		})
	}
}
