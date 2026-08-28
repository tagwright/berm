// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 the berm authors

// Command berm is the label-driven secrets-injection daemon and its companion
// CLI. The daemon holds an age key, decrypts SOPS and age encrypted sources,
// and injects only each container's own declared secrets into it. It never
// stores a secret, never logs a secret value, and never writes plaintext to
// persistent disk.
//
// The subcommands are stubs in this scaffold. Later chunks fill the daemon,
// the resolver, the backend driver, and the delivery mechanisms.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/tagwright/beacon"

	"github.com/tagwright/berm/internal/alert"
	"github.com/tagwright/berm/internal/backend"
	"github.com/tagwright/berm/internal/cli"
	"github.com/tagwright/berm/internal/config"
	"github.com/tagwright/berm/internal/daemon"
	"github.com/tagwright/berm/internal/delivery"
	"github.com/tagwright/berm/internal/version"
)

func main() {
	if err := newRootCmd().Execute(); err != nil {
		os.Exit(1)
	}
}

// newRootCmd builds the berm command tree. Cobra gives the root a "--version"
// flag automatically because Version is set, templated to match the "version"
// subcommand.
func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:           "berm",
		Short:         "Label-driven secrets injection for Docker and Podman",
		SilenceUsage:  true,
		SilenceErrors: true,
		Version:       version.Version,
	}
	root.SetVersionTemplate("berm {{.Version}}\n")

	root.AddCommand(
		newDaemonCmd(),
		newStatusCmd(),
		newStaleCmd(),
		newSuggestCmd(),
		newValidateCmd(),
		newVersionCmd(),
	)
	return root
}

func newDaemonCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "daemon",
		Short: "Run the injection daemon: watch the socket, resolve and deliver",
		RunE:  runDaemon,
	}
	cmd.Flags().String("config", "/etc/berm/berm.yml", "path to berm.yml")
	cmd.Flags().String("socket", "", "berm listen socket (default /run/berm/berm.sock)")
	return cmd
}

// runDaemon loads berm.yml, builds the runtime, backend, opener, and alert sink,
// constructs the daemon, and runs it until SIGINT or SIGTERM, then shuts it down
// cleanly. It is the full daemon subcommand: chunk 6's wiring of every piece the
// earlier chunks built into one running control plane.
func runDaemon(cmd *cobra.Command, _ []string) error {
	cfgPath, _ := cmd.Flags().GetString("config")
	sockFlag, _ := cmd.Flags().GetString("socket")

	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(log)

	cfg, err := config.Load(cfgPath)
	if err != nil {
		return err
	}

	rt, err := daemon.SelectRuntime(cfg)
	if err != nil {
		return err
	}
	defer rt.Close()

	// The backend holds the age key by path only; it never reads the key
	// material itself (the sops subprocess does, at decrypt time).
	be := backend.NewSOPSAge(cfg.AgeKeys)
	opener := delivery.NewConfigOpener(cfg, be)

	sink, err := buildSink()
	if err != nil {
		return err
	}

	d, err := daemon.New(daemon.Config{
		Runtime:    rt,
		Berm:       cfg,
		Opener:     opener,
		Sink:       sink,
		SocketPath: sockFlag,
		Logger:     log,
	})
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	return d.Run(ctx)
}

// buildSink builds the beacon-backed alert sink. Until the operator's full
// beacon channel config lands (a later chunk owns that schema), the sink routes
// diagnostics through beacon's always-available log channel into the daemon
// logger, so alerts are never silently dropped. beacon carries no secret value.
func buildSink() (alert.Sink, error) {
	b, err := beacon.New(beacon.Config{
		Channels: []beacon.ChannelConfig{{Type: "log", MinLevel: beacon.LevelInfo}},
	}, nil)
	if err != nil {
		return nil, err
	}
	return alert.NewBeaconSink(b), nil
}

// loadConfig loads berm.yml at the command's --config flag, the one input every
// companion subcommand needs.
func loadConfig(cmd *cobra.Command) (*config.Config, error) {
	cfgPath, _ := cmd.Flags().GetString("config")
	return config.Load(cfgPath)
}

// hashSource builds the ciphertext-hash source status and stale read the ledger
// against. It is the config-backed Opener, which hashes a source's ciphertext at
// rest and never decrypts, so no command that uses it can surface a value.
func hashSource(cfg *config.Config) daemon.HashSource {
	return delivery.NewConfigOpener(cfg, backend.NewSOPSAge(cfg.AgeKeys))
}

func newStatusCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Report each enabled container's injection state and any warnings",
		RunE:  runStatus,
	}
	cmd.Flags().String("config", "/etc/berm/berm.yml", "path to berm.yml")
	cmd.Flags().String("ledger", daemon.DefaultLedgerPath, "path to the staleness ledger")
	return cmd
}

// runStatus loads config, selects the runtime, and reports each enabled
// container's injection state and warnings. It reads names, paths, hashes, and
// structure only, and never decrypts.
func runStatus(cmd *cobra.Command, _ []string) error {
	cfg, err := loadConfig(cmd)
	if err != nil {
		return err
	}
	rt, err := daemon.SelectRuntime(cfg)
	if err != nil {
		return err
	}
	defer rt.Close()

	ledgerPath, _ := cmd.Flags().GetString("ledger")
	ledger, err := daemon.LoadLedger(ledgerPath)
	if err != nil {
		return err
	}
	return cli.Status(cmd.Context(), os.Stdout, rt, cfg, hashSource(cfg), ledger)
}

func newStaleCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "stale",
		Short: "Report containers whose source changed since their last injection",
		RunE:  runStale,
	}
	cmd.Flags().String("config", "/etc/berm/berm.yml", "path to berm.yml")
	cmd.Flags().String("ledger", daemon.DefaultLedgerPath, "path to the staleness ledger")
	return cmd
}

// runStale is standalone: it loads config and the persisted ledger and reports
// drift against the source ciphertext on disk, without needing the daemon
// running. It compares ciphertext hashes only and never decrypts.
func runStale(cmd *cobra.Command, _ []string) error {
	cfg, err := loadConfig(cmd)
	if err != nil {
		return err
	}
	ledgerPath, _ := cmd.Flags().GetString("ledger")
	ledger, err := daemon.LoadLedger(ledgerPath)
	if err != nil {
		return err
	}
	return cli.Stale(os.Stdout, ledger, hashSource(cfg))
}

func newSuggestCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "suggest <service>",
		Short: "Suggest berm labels for a service from its existing sops secret file",
		Args:  cobra.ExactArgs(1),
		RunE:  runSuggest,
	}
	cmd.Flags().String("config", "/etc/berm/berm.yml", "path to berm.yml (optional, used to locate the source file)")
	cmd.Flags().String("file", "", "path to the service's sops-encrypted secret file (else inferred from berm.yml or convention)")
	cmd.Flags().String("format", "", "source format: dotenv or binary (else inferred from berm.yml or the file extension)")
	return cmd
}

// runSuggest reads only the cleartext key names from the service's existing
// sops-encrypted file and prints ready-to-paste labels and a berm.yml stanza. It
// never runs sops -d and never prints a value. berm.yml is optional here: it is
// only consulted to locate the file, so a parse failure is not fatal when an
// explicit --file is given.
func runSuggest(cmd *cobra.Command, args []string) error {
	file, _ := cmd.Flags().GetString("file")
	format, _ := cmd.Flags().GetString("format")

	var cfg *config.Config
	if c, err := loadConfig(cmd); err == nil {
		cfg = c
	} else if file == "" {
		// Without a config and without an explicit file there is nowhere to look.
		return err
	}

	return cli.Suggest(os.Stdout, cli.SuggestInput{
		Service: args[0],
		File:    file,
		Format:  format,
		Config:  cfg,
	})
}

func newValidateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "validate",
		Short: "Dry-run berm.yml and every enabled container's labels, no injection",
		RunE:  runValidate,
	}
	cmd.Flags().String("config", "/etc/berm/berm.yml", "path to berm.yml")
	return cmd
}

// runValidate dry-runs the manifest with no injection and no decryption, and
// exits nonzero when any container has a validation error so it is usable as a
// CI gate.
func runValidate(cmd *cobra.Command, _ []string) error {
	cfg, err := loadConfig(cmd)
	if err != nil {
		return err
	}
	rt, err := daemon.SelectRuntime(cfg)
	if err != nil {
		return err
	}
	defer rt.Close()
	return cli.Validate(cmd.Context(), os.Stdout, rt, cfg)
}

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the berm version",
		RunE: func(_ *cobra.Command, _ []string) error {
			fmt.Printf("berm %s\n", version.Version)
			return nil
		},
	}
}
