package tunplatform

import (
	"context"
	"errors"
	"testing"
)

func TestJournalUncertainACKRequiresExactReadReceipt(t *testing.T) {
	for _, matched := range []bool{true, false} {
		calls := 0
		client := JournalClient{Launch: Launch{Schema: JournalSchema, Engine: Engine, Epoch: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}
		client.Exchange = func(_ context.Context, r JournalRequest) (JournalState, error) {
			calls++
			if calls == 1 {
				if r.Op != "write_ahead" {
					t.Fatal(r.Op)
				}
				return JournalState{}, errors.New("lost ACK")
			}
			if r.Op != "read" || r.Adapter != nil || len(r.Desired) != 0 {
				t.Fatal("read must be typed read-only")
			}
			seq := r.ExpectedSeq + 1
			if !matched {
				seq++
			}
			return JournalState{Schema: JournalSchema, Engine: Engine, Epoch: r.Epoch, Seq: seq, LastRequest: r.RequestID}, nil
		}
		_, err := client.WriteAhead(context.Background(), 7, Adapter{}, nil)
		if (err == nil) != matched || calls != 2 {
			t.Fatalf("matched=%v calls=%d err=%v", matched, calls, err)
		}
	}
}
func TestJournalRejectsWrongEpochACK(t *testing.T) {
	c := JournalClient{Launch: Launch{Schema: JournalSchema, Engine: Engine, Epoch: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}, Exchange: func(_ context.Context, r JournalRequest) (JournalState, error) {
		return JournalState{Schema: JournalSchema, Engine: Engine, Epoch: "wrong", Seq: 1, LastRequest: r.RequestID}, nil
	}}
	if _, e := c.Begin(context.Background()); e == nil {
		t.Fatal("wrong epoch accepted")
	}
}
