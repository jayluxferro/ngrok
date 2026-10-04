package client

import (
	"fmt"
	"github.com/inconshreveable/mousetrap"
	"ngrok/log"
	"ngrok/util"
	"os"
	"runtime"
	"time"
)

func init() {
	if runtime.GOOS == "windows" {
		if mousetrap.StartedByExplorer() {
			fmt.Println("Don't double-click ngrok!")
			fmt.Println("You need to open cmd.exe and run it from the command line!")
			time.Sleep(5 * time.Second)
			os.Exit(1)
		}
	}
}

func Main() {
	// parse options
	opts, err := ParseArgs()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	// set up logging. An unrecognized -log-level is a startup error, not a
	// silent fall-back to DEBUG (see log.LogTo): a level the operator did not
	// ask for must stop the process here, where it can be read.
	if err := log.LogTo(opts.logto, opts.loglevel, opts.logformat); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	// read configuration file
	config, err := LoadConfiguration(opts)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	// seed random number generator
	seed, err := util.RandomSeed()
	if err != nil {
		fmt.Printf("Couldn't securely seed the random number generator!")
		os.Exit(1)
	}
	util.InitGlobalRand(seed)

	NewController().Run(config)
}
