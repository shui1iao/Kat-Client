// Isolated fixed Xray client process. Never a production dependency.
package main

import (
	"fmt"
	core "github.com/xtls/xray-core/core"
	_ "github.com/xtls/xray-core/main/distro/all"
	"io"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "review-keyupdate" {
		reviewKeyUpdate()
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "authprobe" {
		authprobe()
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "halfclose" {
		halfclose()
		return
	}
	b, e := io.ReadAll(io.LimitReader(os.Stdin, 1<<20))
	if e != nil {
		panic(e)
	}
	server, e := core.StartInstance("json", b)
	if e != nil {
		panic(e)
	}
	defer server.Close()
	fmt.Println("XRAY_READY")
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGTERM, syscall.SIGINT)
	<-ch
}
