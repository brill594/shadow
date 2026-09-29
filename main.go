package main

import (
	"flag"
	"fmt"
	"log"
	"os"
)

func main() {
	if len(os.Args) < 2 || (os.Args[1] != "render" && os.Args[1] != "run") {
		fmt.Fprintln(os.Stderr, "usage: lan-service-gateway render|run -config path [-out-dir path]")
		os.Exit(2)
	}
	command := os.Args[1]
	flags := flag.NewFlagSet(command, flag.ExitOnError)
	path := flags.String("config", "/tmp/lan-service-gateway.conf", "validated runtime config")
	outDir := flags.String("out-dir", "/usr/share/nftables.d", "firewall4 include directory")
	applyPath := flags.String("apply", "/tmp/lan-service-gateway.apply", "live nftables update file")
	flags.Parse(os.Args[2:])
	c, err := readConfig(*path)
	if err == nil {
		var lan, wan interfaceState
		lan, err = currentInterface(c.lanDevice)
		if err == nil {
			wan, err = currentInterface(c.wanDevice)
		}
		if err == nil {
			if command == "render" {
				var nat, forward string
				nat, forward, err = renderRules(c, lan, wan)
				if err == nil {
					err = writeRules(*outDir, *applyPath, nat, forward)
				}
			} else {
				err = runDiscovery(c, lan, wan)
			}
		}
	}
	if err != nil {
		log.Fatal(err)
	}
}
