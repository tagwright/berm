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

// notImplemented is the shared stub body for every subcommand until its chunk
// lands. It reports the gap honestly rather than pretending to act.
func notImplemented(name string) func(*cobra.Command, []string) error {
	return func(_ *cobra.Command, _ []string) error {
		return fmt.Errorf("berm %s: not implemented", name)
	}
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

func newStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Report each enabled container's injection state and any warnings",
		RunE:  notImplemented("status"),
	}
}

func newStaleCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "stale",
		Short: "Report containers whose source changed since their last injection",
		RunE:  notImplemented("stale"),
	}
}

func newSuggestCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "suggest",
		Short: "Suggest berm labels for a container from its known secret shape",
		RunE:  notImplemented("suggest"),
	}
}

func newValidateCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "validate",
		Short: "Validate berm.yml and every enabled container's labels",
		RunE:  notImplemented("validate"),
	}
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
