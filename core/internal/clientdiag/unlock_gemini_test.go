package clientdiag

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// These are classification sentinels, not captured Google successes. Anonymous
// public app HTML has no documented acceptance schema; no green fixture is made.
func TestGeminiSingleAnonymousRequestAndNoInferredUnlock(t *testing.T) {
	for _, body := range []string{
		`<title>Google Gemini</title><a>Sign in</a><chat-app-orchestrator id="app-root"></chat-app-orchestrator>`,
		`<script>window.WIZ_global_data = {"cfb2h":"boq_gemini-web-uiserver_20261102.01_p1"};const x=[null,2,1,200,"SGP"];</script>`,
		`<h1>Gemini</h1><p>Available in 230 countries</p>`,
		`<script>const text="Gemini isn't available in your country yet";</script>`,
		`<div aria-hidden="true"><h1>Gemini isn't available in your country yet</h1></div>`,
		`<p>For help if Gemini isn't available in your country yet, sign in.</p>`,
	} {
		calls := 0
		v := Detect(context.Background(), "Gemini", func(_ context.Context, method, u string) (Page, error) {
			calls++
			if method != "GET" || u != "https://gemini.google.com/app?hl=en" {
				t.Fatal("unexpected Gemini request", method, u)
			}
			return Page{Status: 200, Body: body, URL: u}, nil
		})
		if calls != 1 || v.Result != "unknown" || v.Region != "" || v.HTTPStatus != 200 || !strings.Contains(v.Reason, "[anonymous_evidence]") {
			t.Fatal("unproven functional/region claim or extra request", calls, v)
		}
	}
}

func TestGeminiChallengeAndErrorPrecedence(t *testing.T) {
	denial := "<h1>Gemini isn’t available in your country yet.</h1>"
	for _, tc := range []struct {
		status     int
		body, want string
	}{
		{200, denial, "blocked"},
		{403, denial, "unknown"},
		{200, "<p>Our systems have detected unusual traffic from your computer network.</p>" + denial, "challenge"},
		{403, `<form id="challenge-form"></form>` + denial, "challenge"},
		{200, `<script>{"captchaEnabled":true,"recaptchaKey":"public"}</script>` + denial, "blocked"},
	} {
		v := Detect(context.Background(), "Gemini", func(context.Context, string, string) (Page, error) {
			return Page{Status: tc.status, Body: tc.body}, nil
		})
		if v.Result != tc.want || v.HTTPStatus != tc.status || v.Region != "" {
			t.Fatal(tc, v)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	v := Detect(ctx, "Gemini", func(context.Context, string, string) (Page, error) {
		cancel()
		return Page{Status: 200, Body: denial}, nil
	})
	if v.Result != "failed" || !strings.Contains(v.Reason, "[canceled]") {
		t.Fatal("cancel was hidden by page", v)
	}
	v = Detect(context.Background(), "Gemini", func(context.Context, string, string) (Page, error) {
		return Page{Status: 200}, errors.New("PRIVATE_SENTINEL")
	})
	if v.Result != "failed" || strings.Contains(v.Reason, "PRIVATE_SENTINEL") {
		t.Fatal("transport failure leaked", v)
	}
}
