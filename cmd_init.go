package main

import (
	"fmt"
	"os"
)

func cmdInit() error {
	path := keyfile()
	if _, err := os.Stat(path); err == nil {
		fmt.Println("==> key already exists at", path)
	} else {
		fmt.Println("==> generating a new per-machine key")
		if err := ensureKey(); err != nil {
			return err
		}
	}
	fmt.Println()
	fmt.Println("This machine's PUBLIC key (safe to share):", pubkey())
	fmt.Println("PRIVATE key lives at:", keyfile(), "(back this up to your password manager)")
	return nil
}
