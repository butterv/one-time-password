package main

import (
	"flag"
	"fmt"

	"github.com/istsh/one-time-password/recovery"
)

var (
	option  = flag.Bool("option", false, "the flag of using custom option")
	letters = flag.String("letters", "", "the candidate characters used to generate random string")
	length  = flag.Uint("length", 8, "the length of generated random string")
	count   = flag.Uint("count", 10, "the count of random string")
	format  = flag.Int("format", 0, "the format of recovery code")
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
		if *format != 0 {
			err := o.SetFormat(recovery.Format(*format))
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
