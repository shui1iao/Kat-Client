package clientdiag

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func geminiConfigPage(alpha3 string) string {
	return `<!DOCTYPE html><html><head><title>Google Gemini</title></head><body>` +
		`<script>window.WIZ_global_data={};var _bar_={CONFIG:[[[0,"www.gstatic.com",` +
		`"og.qtm.en_US","example","en","658",0,[4,2,"","","","961884838","0"],` +
		`null,"id",null,0,"og.qtm",` +
		`"a","b","",2,1,200,"` + alpha3 + `",null,null,"269","658",1,null,null,103135050,null,0,0,0,0]]]}` +
		`</script></body></html>`
}

func TestGeminiClassifyAndUnsupportedCountries(t *testing.T) {
	for _, tc := range []struct {
		alpha3, wantResult, wantRegion string
	}{
		{"USA", "unlocked", "US"},
		{"SGP", "unlocked", "SG"},
		{"JPN", "unlocked", "JP"},
		{"HKG", "unlocked", "HK"},
		{"FRA", "unlocked", "FR"},
		{"RUS", "blocked", "RU"},
		{"BLR", "blocked", "BY"},
		{"CHN", "blocked", "CN"},
		{"PRK", "blocked", "KP"},
		{"IRN", "blocked", "IR"},
		{"CUB", "blocked", "CU"},
		{"SYR", "blocked", "SY"},
		{"ZZZ", "unknown", ""},
		{"xaa", "unknown", ""},
	} {
		calls := 0
		v := Detect(context.Background(), "Gemini", func(_ context.Context, method, u string) (Page, error) {
			calls++
			if method != "GET" || u != "https://gemini.google.com/app" {
				t.Fatal("unexpected Gemini request", method, u)
			}
			return Page{Status: 200, Body: geminiConfigPage(tc.alpha3), URL: u}, nil
		})
		if calls != 1 || v.Result != tc.wantResult || v.Region != tc.wantRegion || v.HTTPStatus != 200 {
			t.Fatalf("alpha3=%s got %+v calls=%d", tc.alpha3, v, calls)
		}
	}
	for _, body := range []string{
		`<title>Google Gemini</title><a>Sign in</a><chat-app-orchestrator id="app-root"></chat-app-orchestrator>`,
		`<h1>Gemini</h1><p>Available in 230 countries</p>`,
		`<script>const text="Gemini isn't available in your country yet";</script>`,
		`<div aria-hidden="true"><h1>Gemini isn't available in your country yet</h1></div>`,
		`<script>const a=[null,2,1,200,"USA"];const b=[null,2,1,200,"SGP"];</script>`,
	} {
		v := Detect(context.Background(), "Gemini", func(_ context.Context, method, u string) (Page, error) {
			return Page{Status: 200, Body: body, URL: u}, nil
		})
		if v.Result != "unknown" || v.Region != "" || !strings.Contains(v.Reason, "[schema]") {
			t.Fatal("unexpected verdict for missing/conflicting Gemini region", v)
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
		{200, "<p>Our systems have detected unusual traffic from your computer network.</p>" + geminiConfigPage("USA"), "challenge"},
		{403, `<form id="challenge-form"></form>` + geminiConfigPage("USA"), "challenge"},
		{403, `<script>window._cf_chl_opt={};</script>` + geminiConfigPage("CHN"), "challenge"},
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
		return Page{Status: 200, Body: geminiConfigPage("USA")}, nil
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

func TestGooglePrimaryVerdictIndependentOfAuxiliaryRegion(t *testing.T) {
	// Google primary unlocked verdict, HTTPStatus and stage must stay intact
	// even when auxiliary region request fails, 403s, challenges, times out or conflicts.
	const (
		service     = "Google"
		primaryBody = `<!DOCTYPE html><html><body>normal search results</body></html>`
		stage       = "Google Search 匿名验证码检测"
	)
	for _, mode := range []string{"error", "http403", "challenge", "conflict", "short_budget"} {
		ctx := context.Background()
		var cancel context.CancelFunc = func() {}
		if mode == "short_budget" {
			ctx, cancel = context.WithTimeout(ctx, 500*time.Millisecond)
		}
		calls := 0
		v := Detect(ctx, service, func(reqCtx context.Context, _, u string) (Page, error) {
			calls++
			if calls == 1 {
				return Page{Status: 200, Body: primaryBody, URL: u}, nil
			}
			switch mode {
			case "error":
				return Page{Status: 502}, errors.New("auxiliary error")
			case "http403":
				return Page{Status: 403, Body: "Forbidden"}, nil
			case "challenge":
				return Page{Status: 403, Body: "<title>Just a moment</title>cf_chl_opt"}, nil
			default:
				return Page{Status: 200, Body: `"ja_JP" "en_SG"`}, nil
			}
		})
		cancel()
		if v.Result != "unlocked" || v.Region != "" || v.HTTPStatus != 200 || !strings.HasPrefix(v.Reason, stage+"：") {
			t.Fatalf("%s/%s downgraded primary verdict or overwrote HTTP/stage: %+v", service, mode, v)
		}
		if mode == "short_budget" && calls != 1 {
			t.Fatalf("%s short budget did not skip auxiliary request: calls=%d", service, calls)
		}
	}
	// Conflicting inline region on primary Google page clears region without downgrading unlocked.
	v := Detect(context.Background(), "Google", func(_ context.Context, _, u string) (Page, error) {
		return Page{Status: 200, Body: `<!DOCTYPE html><html><body>"ja_JP" "en_SG"</body></html>`, URL: u}, nil
	})
	if v.Result != "unlocked" || v.Region != "" || v.HTTPStatus != 200 {
		t.Fatal("Google conflicting inline region downgraded primary verdict", v)
	}
}
