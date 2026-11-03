package main

import (
	"context"
	"flag"
	"fmt"
	"github.com/shui1iao/Kat/internal/clientcore"
	"os"
	"os/signal"
)

func main() {
	fs := flag.NewFlagSet("kat-client-core", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	workspace := fs.String("workspace", "", "absolute per-user data directory")
	if e := fs.Parse(os.Args[1:]); e != nil {
		os.Exit(2)
	}
	h, e := clientcore.Open(*workspace)
	if e != nil {
		if de, ok := e.(*clientcore.Error); ok && de.Code == "configuration_conflict" {
			// Fixed allowlisted marker only; never forward arbitrary config errors/paths.
			fmt.Fprintln(os.Stderr, "kat-client-core: configuration_conflict")
		} else {
			fmt.Fprintln(os.Stderr, "kat-client-core: workspace unavailable or invalid")
		}
		os.Exit(1)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	go func() { <-ctx.Done(); os.Stdin.Close() }()
	e = h.Serve(ctx, os.Stdin, os.Stdout)
	ce := h.Close()
	if e != nil || ce != nil {
		fmt.Fprintln(os.Stderr, "kat-client-core: closed after input or drain failure")
		os.Exit(1)
	}
}
