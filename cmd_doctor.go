package main

import (
	"fmt"
	"os"
	"runtime/debug"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

func newDoctorCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "doctor",
		Short: "show key status and embedded sops/age versions",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			return runDoctor()
		},
	}
}

func runDoctor() error {
	path := keyfile()
	if _, err := os.Stat(path); err == nil {
		fmt.Println("key:   ", path)
		fmt.Println("pubkey:", color.CyanString(pubkey()))
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
