package server

import (
	"fmt"
	"strings"
)

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
	if opts.adminRate < 0 {
		return fmt.Errorf("-adminRate cannot be negative")
	}
	if opts.adminAuth != "" && !strings.Contains(opts.adminAuth, ":") {
		return fmt.Errorf("-adminAuth must be user:password")
	}
	if opts.statusAuth != "" && !strings.Contains(opts.statusAuth, ":") {
		return fmt.Errorf("-statusAuth must be user:password")
	}
	if opts.adminAddr == "" && (opts.adminAuth != "" || opts.adminToken != "") {
		return fmt.Errorf("admin auth/token requires -adminAddr")
	}
	return nil
}
