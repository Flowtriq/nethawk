package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"syscall"

	"github.com/Flowtriq/nethawk/internal/capture"
	"github.com/Flowtriq/nethawk/internal/ui"
)

var version = "0.1.0"

func main() {
	iface := flag.String("i", "", "network interface to capture on")
	threshold := flag.Int("t", 50000, "PPS threshold for attack detection")
	jsonMode := flag.Bool("json", false, "output JSON instead of TUI")
	listIfaces := flag.Bool("list", false, "list available network interfaces")
	demoMode := flag.Bool("demo", false, "run with simulated traffic (for testing)")
	showVersion := flag.Bool("version", false, "show version")
	flag.Parse()

	if *showVersion {
		fmt.Printf("nethawk %s (%s/%s)\n", version, runtime.GOOS, runtime.GOARCH)
		os.Exit(0)
	}

	if *listIfaces {
		ifaces, err := capture.ListInterfaces()
		if err != nil {
			fmt.Fprintf(os.Stderr, "error listing interfaces: %v\n", err)
			os.Exit(1)
		}
		for _, i := range ifaces {
			fmt.Println(i)
		}
		os.Exit(0)
	}

	var src capture.Source

	if *demoMode {
		src = capture.NewDemo(*threshold)
	} else {
		if os.Geteuid() != 0 {
			fmt.Fprintln(os.Stderr, "nethawk requires root privileges for packet capture.")
			fmt.Fprintln(os.Stderr, "Run with: sudo nethawk")
			os.Exit(1)
		}

		ifaceName := *iface
		if ifaceName == "" {
			var err error
			ifaceName, err = capture.DefaultInterface()
			if err != nil {
				fmt.Fprintf(os.Stderr, "error finding default interface: %v\n", err)
				fmt.Fprintln(os.Stderr, "Specify one with: nethawk -i <interface>")
				fmt.Fprintln(os.Stderr, "List interfaces with: nethawk -list")
				os.Exit(1)
			}
		}

		c, err := capture.New(ifaceName, *threshold)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error starting capture on %s: %v\n", ifaceName, err)
			os.Exit(1)
		}
		src = c
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go src.Start()

	if *jsonMode {
		runJSON(src, sigCh)
	} else {
		runTUI(src, sigCh)
	}
}

func runJSON(src capture.Source, sigCh chan os.Signal) {
	ticker := src.Ticker()
	for {
		select {
		case <-sigCh:
			src.Stop()
			return
		case snap := <-ticker:
			fmt.Println(snap.JSON())
		}
	}
}

func runTUI(src capture.Source, sigCh chan os.Signal) {
	app := ui.New(src)
	go func() {
		<-sigCh
		src.Stop()
		app.Quit()
	}()
	if err := app.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}
