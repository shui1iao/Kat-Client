package main

import (
	"context"
	"flag"
	"fmt"
	"github.com/shui1iao/Kat/internal/clientcore"
	"github.com/shui1iao/Kat/internal/elevated"
	"github.com/shui1iao/Kat/internal/userio"
	"os"
	"os/signal"
	"runtime/debug"
)

func main() {
	if os.Getenv("GOTRACEBACK") == "" {
		debug.SetTraceback("all")
	}
	fs := flag.NewFlagSet("kat-client-core", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	workspace := fs.String("workspace", "", "absolute per-user data directory")
	high := fs.Bool("elevated", false, "fixed installed elevated role")
	lease := fs.String("launch-lease", "", "fixed launch lease")
	servicePID := fs.Uint("service-pid", 0, "SCM service identity")
	serviceStamp := fs.Uint64("service-stamp", 0, "SCM service creation")
	if e := fs.Parse(os.Args[1:]); e != nil || fs.NArg() != 0 {
		os.Exit(2)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	var h *clientcore.Host
	var e error
	var session *elevated.Session
	if *high {
		userio.RequireMedium()
		if *workspace != "" || *servicePID > uint(^uint32(0)) {
			os.Exit(2)
		}
		session, e = elevated.Open(ctx, *lease, uint32(*servicePID), *serviceStamp)
		if e == nil {
			defer session.Close()
			var activation elevated.Activation
			activation, e = session.Wait(ctx)
			if e == nil {
				h, e = clientcore.OpenHandover(session.Binding.Workspace, activation.Checkpoint)
				if e == nil {
					e = h.AttachElevated(session)
				}
				if ae := session.Activated(activation, e); e == nil {
					e = ae
				}
			}
		}
	} else {
		if elevated.Elevated() || *lease != "" || *servicePID != 0 || *serviceStamp != 0 {
			userio.RequireMedium()
			fmt.Fprintln(os.Stderr, "kat-client-core: authenticated administrator launch required")
			os.Exit(1)
		}
		h, e = clientcore.Open(*workspace)
	}
	if e != nil {
		if de, ok := e.(*clientcore.Error); ok && de.Code == "configuration_conflict" {
			fmt.Fprintln(os.Stderr, "kat-client-core: configuration_conflict")
		} else {
			fmt.Fprintln(os.Stderr, "kat-client-core: workspace unavailable or invalid")
		}
		if *high {
			os.Exit(elevated.BootstrapExit(e))
		}
		os.Exit(1)
	}
	if session != nil {
		// This typed compatibility entry is supplied by the LOG owner. The old Serve
		// entry remains stdio, including its original timing/admission observations.
		e = h.ServeTransport(ctx, session.Reader, session.Conn, clientcore.TransportNamedPipe)
	} else {
		go func() { <-ctx.Done(); os.Stdin.Close() }()
		e = h.Serve(ctx, os.Stdin, os.Stdout)
	}
	ce := h.Close()
	if e != nil || ce != nil {
		fmt.Fprintln(os.Stderr, "kat-client-core: closed after input or drain failure")
		os.Exit(1)
	}
}
