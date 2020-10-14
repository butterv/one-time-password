package main

import (
	"flag"
	"fmt"

	"github.com/istsh/one-time-password/recovery"
)

var (
	length = flag.Uint("length", 8, "")
	count  = flag.Uint("count", 10, "")
)

func main() {
	flag.Parse()

	codes, err := recovery.GenerateRecoveryCodes(*length, *count)
	if err != nil {
		panic(err)
	}

	for i, code := range codes {
		fmt.Printf("%02d: %s\n", i, code)
	}
}
