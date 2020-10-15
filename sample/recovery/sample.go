package main

import (
	"flag"
	"fmt"

	"github.com/istsh/one-time-password/recovery"
)

var (
	option  = flag.Bool("option", false, "")
	letters = flag.String("letters", "", "")
	length  = flag.Uint("length", 8, "")
	count   = flag.Uint("count", 10, "")
)

func main() {
	flag.Parse()

	o := recovery.NewOption()
	if *option {
		if len(*letters) > 0 {
			err := o.SetLetters(*letters)
			if err != nil {
				panic(err)
			}
		}
		if *length != 0 {
			err := o.SetLength(*length)
			if err != nil {
				panic(err)
			}
		}
		if *count != 0 {
			err := o.SetCount(*count)
			if err != nil {
				panic(err)
			}
		}
	}

	codes, err := recovery.GenerateRecoveryCodesWithOption(o)
	if err != nil {
		panic(err)
	}

	for i, code := range codes {
		fmt.Printf("%02d: %s\n", i, code)
	}
}
