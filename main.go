package main

import (
	"fmt"
	"os"
	"runtime"

	"github.com/jessevdk/go-flags"
)

var version string

const UNKNOWN = 3
const CRITICAL = 2
const WARNING = 1
const OK = 0

func printVersion() {
	fmt.Printf(`%s Compiler: %s %s`,
		version,
		runtime.Compiler,
		runtime.Version())
}

func main() {
	os.Exit(_main())
}

func _main() int {
	opt := Opt{}
	psr := flags.NewParser(&opt, flags.Default)
	_, err := psr.Parse()
	if err != nil {
		os.Exit(UNKNOWN)
	}

	if opt.Version {
		printVersion()
		return OK
	}

	if opt.TCP4 && opt.TCP6 {
		fmt.Printf("Both tcp4 and tcp6 are specified\n")
		return UNKNOWN
	}

	if opt.VerifySNI && opt.SNI == "" {
		fmt.Printf("--sni is required when use --verify-sni\n")
		return UNKNOWN
	}

	msg, err := opt.Verify()
	if err != nil {
		fmt.Println(err.Error())
		return CRITICAL
	}
	fmt.Println(msg)
	return OK
}
