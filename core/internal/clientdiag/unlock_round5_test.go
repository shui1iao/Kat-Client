package clientdiag

import (
	"context"
	"reflect"
	"strings"
	"testing"
)

func TestRound5OnlyFourServicesAndRemovedServicesNeverFetch(t *testing.T) {
	want := []string{"ChatGPT", "Gemini", "Claude", "Google", "YouTube", "Netflix", "Disney+"}
	if !reflect.DeepEqual(Services, want) {
		t.Fatal(Services)
	}
	for _, name := range []string{"TikTok", "YouTube Premium"} {
		calls := 0
		v := Detect(context.Background(), name, func(context.Context, string, string) (Page, error) { calls++; return Page{}, nil })
		if calls != 0 || v.Result != "failed" || !strings.Contains(v.Reason, "[unsupported]") {
			t.Fatal(name, v, calls)
		}
	}
}
