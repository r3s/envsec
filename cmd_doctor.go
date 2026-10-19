package main

import (
	"fmt"
	"os"
	"runtime/debug"
)

func cmdDoctor() error {
	path := keyfile()
	if _, err := os.Stat(path); err == nil {
		fmt.Println("key:   ", path)
		fmt.Println("pubkey:", pubkey())
	} else {
		fmt.Println("key:   MISSING — run 'envsec init'")
	}
	if bi, ok := debug.ReadBuildInfo(); ok {
		for _, d := range bi.Deps {
			switch d.Path {
			case "github.com/getsops/sops/v3":
				fmt.Println("sops:  ", d.Version)
			case "filippo.io/age":
				fmt.Println("age:   ", d.Version)
			}
		}
	}
	return nil
}
