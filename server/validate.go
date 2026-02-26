package server

import "fmt"

func validateOptions(opts *Options) error {
	if (opts.tlsCrt == "") != (opts.tlsKey == "") {
		return fmt.Errorf("both -tlsCrt and -tlsKey must be set together")
	}
	if opts.maxMsgBytes <= 0 {
		return fmt.Errorf("-maxMsgBytes must be > 0")
	}
	if opts.authRate < 0 || opts.publicRate < 0 || opts.maxConnPerIP < 0 {
		return fmt.Errorf("rate/connection limits cannot be negative")
	}
	if opts.enablePprof && opts.adminAddr == "" {
		return fmt.Errorf("-pprof requires -adminAddr")
	}
	return nil
}
