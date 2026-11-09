// Isolated real runtime crash child for c46; never used by the installed product.
package main

import (
	"fmt"
	"os"
	"sync"
)

func main() {
	fmt.Fprintln(os.Stderr, "routine stderr is not persisted")
	mode := "panic"
	if len(os.Args) > 1 {
		mode = os.Args[1]
	}
	if mode == "oversize" {
		var ready sync.WaitGroup
		ready.Add(2000)
		for i := 0; i < 2000; i++ {
			go waiting(i, &ready)
		}
		ready.Wait()
	}
	if mode == "panic" {
		panic("c46 isolated verification panic")
	}
	var m sync.Mutex
	m.Unlock()
}
func waiting(n int, ready *sync.WaitGroup) { ready.Done(); select {} }
