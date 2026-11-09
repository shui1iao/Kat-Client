package kernel

import (
	"context"
	"testing"
	"time"
)

func TestC46UDPAssociationTerminalOutcomes(t *testing.T) {
	cases := []struct {
		name, result, previous, code, want string
		recorded                           bool
	}{
		{name: "no datagrams is neutral", result: "idle", want: "idle"},
		{name: "normal datagram is successful", result: "ok", want: "ok"},
		{name: "prior error is preserved", result: "idle", previous: "error", code: "udp_send_failed", want: "error", recorded: true},
		{name: "prior reject is preserved", result: "idle", previous: "rejected", code: "rejected", want: "rejected", recorded: true},
		{name: "association error is not idle", result: "udp_association_failed", want: "error"},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			var events []ConnectionEvent
			s := &Server{core: &core{connectionSink: func(e ConnectionEvent) { events = append(events, e) }}}
			f := &flow{s: s, id: 1, network: "udp", start: time.Now(), lastOutcome: tt.previous, lastCode: tt.code, eventRecorded: tt.recorded}
			f.end(tt.result)
			if len(events) == 0 {
				t.Fatal("missing terminal record")
			}
			got := events[len(events)-1]
			if !got.Ended || got.Outcome != tt.want {
				t.Fatalf("terminal ended=%v outcome=%q, want %q", got.Ended, got.Outcome, tt.want)
			}
			if tt.want == "idle" && (got.Code != "udp_no_datagrams" || len(events) != 1 || got.Up != 0 || got.Down != 0) {
				t.Fatalf("idle was rewritten or duplicated: %+v", events)
			}
			if tt.recorded && got.Code != tt.code {
				t.Fatalf("lost recorded cause %q", got.Code)
			}
			if s.closedSize != 1 {
				t.Fatal("terminal record hidden")
			}
		})
	}
}

func TestC46ZeroPayloadDatagramIsStillAReceivedDatagram(t *testing.T) {
	a := &udpAssociation{server: &Server{cfg: Config{Limits: Limits{UDPQueue: 1, UDPQueueBytes: 1024}}}, ctx: context.Background(), queue: make(chan packet, 1)}
	a.enqueue(packet{target: Address{Host: "127.0.0.1", Port: 53}, payload: []byte{}})
	if !a.receivedDatagram.Load() || len(a.queue) != 1 {
		t.Fatal("valid zero-payload datagram mistaken for no datagrams")
	}
}
