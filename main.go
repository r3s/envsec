// Command envsec manages per-machine encrypted .env files using sops + age.
package main

import (
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

// exitError carries a child process's exit status through cobra so main can
// exit with it after all deferred cleanup has run.
type exitError struct{ code int }

func (e exitError) Error() string { return fmt.Sprintf("exit status %d", e.code) }

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	if err := setKeyEnv(); err != nil {
		printErr(err)
		return 1
	}
	root := newRootCmd()
	root.SetArgs(args)
	if err := root.Execute(); err != nil {
		var ee exitError
		if errors.As(err, &ee) {
			return ee.code
		}
		printErr(err)
		return 1
	}
	return 0
}

func printErr(err error) {
	fmt.Fprintln(os.Stderr, color.New(color.FgRed, color.Bold).Sprintf("envsec: %v", err))
}

func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:                   "envsec",
		Short:                 "per-machine encrypted .env workflow (sops + age, compiled in)",
		SilenceErrors:         true,
		SilenceUsage:          true,
		CompletionOptions:     cobra.CompletionOptions{DisableDefaultCmd: true},
		DisableFlagsInUseLine: true,
	}
	root.AddCommand(
		newInitCmd(),
		newDoctorCmd(),
		newSealCmd(),
		newRunCmd(),
		newEditCmd(),
		newExportCmd(),
		newAddRecipientCmd(),
	)
	// Capture cobra's default template help before overriding the root, so
	// subcommands keep their standard per-command help.
	defaultHelp := root.HelpFunc()
	root.SetHelpFunc(func(c *cobra.Command, args []string) {
		if c.Parent() == nil {
			rootHelp(c, args)
		} else {
			defaultHelp(c, args)
		}
	})
	root.Run = func(c *cobra.Command, _ []string) { c.Help() }
	return root
}

// rootHelp prints the curated, grouped help overview for the bare command.
func rootHelp(c *cobra.Command, _ []string) {
	w := c.OutOrStdout()
	color.New(color.Bold).Fprintf(w, "envsec — per-machine encrypted .env workflow (sops + age, compiled in)\n\n")
	fmt.Fprintln(w, "USAGE")
	fmt.Fprintln(w, "    envsec <command> [flags] [-f FILE] [-- cmd...]")

	groups := []struct {
		name  string
		names []string
	}{
		{"SETUP  (once per machine)", []string{"init", "doctor"}},
		{"SECRETS", []string{"seal", "run", "edit", "export"}},
		{"ACCESS", []string{"addrecipient"}},
	}
	for _, g := range groups {
		fmt.Fprintln(w)
		fmt.Fprintln(w, g.name)
		for _, name := range g.names {
			if sc := findSubCommand(c, name); sc != nil {
				fmt.Fprintf(w, "    %-30s %s\n", sc.Use, sc.Short)
			}
		}
	}

	fmt.Fprintln(w)
	fmt.Fprintln(w, "FLAGS")
	fmt.Fprintln(w, "    -f, --file FILE   secrets file (default: .env.local); sealed file: FILE.enc.env")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "EXAMPLES")
	fmt.Fprintln(w, "    envsec init")
	fmt.Fprintln(w, "    envsec seal -- ./scripts/pull-secrets.sh")
	fmt.Fprintln(w, "    envsec run -- npm run dev")
	fmt.Fprintln(w, "    envsec addrecipient age1mn2...")
	fmt.Fprintln(w, "    envsec edit")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "FIRST-TIME FLOW")
	fmt.Fprintln(w, "    1. envsec init                 # once per machine")
	fmt.Fprintln(w, "    2. envsec seal -- <pull cmd>   # fetch & encrypt, commit FILE.enc.env")
	fmt.Fprintln(w, "    3. envsec run -- <cmd>         # daily use; secrets never touch disk")
	fmt.Fprintln(w, "    Team mates: they send you the public key from 'envsec doctor', you run")
	fmt.Fprintln(w, "    'envsec addrecipient <pubkey>', they pull and run.")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "KEY")
	fmt.Fprintln(w, "    Private: $SOPS_AGE_KEY_FILE or ~/.config/sops/age/keys.txt  (back it up)")
	fmt.Fprintln(w, "    Public:  'envsec doctor' / 'envsec init' — safe to share.")
}

func findSubCommand(c *cobra.Command, name string) *cobra.Command {
	for _, sc := range c.Commands() {
		if sc.Name() == name {
			return sc
		}
	}
	return nil
}

func addFileFlag(cmd *cobra.Command) {
	cmd.Flags().StringP("file", "f", ".env.local", "secrets file")
}

func fileFlag(c *cobra.Command) string {
	f, _ := c.Flags().GetString("file")
	return f
}

// onInterrupt runs cleanup when the process is interrupted and then exits.
// The returned stop function must be deferred to release the signal handler.
func onInterrupt(cleanup func()) (stop func()) {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	done := make(chan struct{})
	go func() {
		select {
		case <-done:
		case <-sig:
			cleanup()
			os.Exit(130)
		}
	}()
	return func() {
		signal.Stop(sig)
		close(done)
	}
}
