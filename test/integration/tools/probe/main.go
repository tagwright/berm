// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 the berm authors

// Command probe is the in-container assertion helper for the berm integration
// harness. It runs inside berm-itest-* app containers so the host-side driver
// can prove properties that are only observable from inside the container: the
// filesystem type a secret landed on (statfs), a delivered file's byte hash and
// numeric owner and mode, and the process environment of PID 1 (where an
// env-delivered secret lives, and nowhere else).
//
// It is a throwaway test tool in its own module, standard library only, so it
// builds offline with no external dependency and never drags in berm's own
// packages. It carries no secret of its own: it only reports on what berm
// delivered, and only the sha256 of a file, never its plaintext, crosses back
// to the driver.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strings"
	"syscall"
	"time"
)

// tmpfs and ramfs superblock magics, the only backings where a secret never
// touches persistent disk.
const (
	tmpfsMagic = 0x01021994
	ramfsMagic = 0x858458f6
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "probe: need a subcommand")
		os.Exit(2)
	}
	switch os.Args[1] {
	case "hold":
		// Block forever so an exec'd app keeps the container alive for the
		// driver to exec assertions against. This becomes PID 1 in the exec form.
		// A timer sleep loop (not select{}) keeps a runnable timer so the Go
		// runtime's all-goroutines-asleep deadlock detector never fires.
		for {
			time.Sleep(time.Hour)
		}
	case "statfs":
		os.Exit(cmdStatfs(os.Args[2:]))
	case "sha256":
		os.Exit(cmdSha256(os.Args[2:]))
	case "stat":
		os.Exit(cmdStat(os.Args[2:]))
	case "environ":
		os.Exit(cmdEnviron(os.Args[2:]))
	case "has":
		os.Exit(cmdHas(os.Args[2:]))
	case "waitfile":
		os.Exit(cmdWaitfile(os.Args[2:]))
	default:
		fmt.Fprintf(os.Stderr, "probe: unknown subcommand %q\n", os.Args[1])
		os.Exit(2)
	}
}

// cmdStatfs prints the filesystem type name of the mount backing a path:
// "tmpfs", "ramfs", or "other:0x<magic>". The driver asserts a delivered secret
// lives on tmpfs or ramfs, never a persistent filesystem.
func cmdStatfs(args []string) int {
	if len(args) != 1 {
		fmt.Fprintln(os.Stderr, "usage: probe statfs <path>")
		return 2
	}
	var st syscall.Statfs_t
	if err := syscall.Statfs(args[0], &st); err != nil {
		fmt.Fprintf(os.Stderr, "statfs %s: %v\n", args[0], err)
		return 1
	}
	switch uint64(st.Type) {
	case tmpfsMagic:
		fmt.Println("tmpfs")
	case ramfsMagic:
		fmt.Println("ramfs")
	default:
		fmt.Printf("other:0x%x\n", uint64(st.Type))
	}
	return 0
}

// cmdSha256 prints the hex sha256 of a file's bytes. Only the hash crosses back
// to the driver, never the plaintext, so a secret's byte-exactness is proven
// without the harness ever printing the value.
func cmdSha256(args []string) int {
	if len(args) != 1 {
		fmt.Fprintln(os.Stderr, "usage: probe sha256 <path>")
		return 2
	}
	f, err := os.Open(args[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "open %s: %v\n", args[0], err)
		return 1
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		fmt.Fprintf(os.Stderr, "read %s: %v\n", args[0], err)
		return 1
	}
	fmt.Println(hex.EncodeToString(h.Sum(nil)))
	return 0
}

// cmdStat prints "uid gid octalmode" for a file, so the driver can assert the
// numeric owner and permission bits berm applied.
func cmdStat(args []string) int {
	if len(args) != 1 {
		fmt.Fprintln(os.Stderr, "usage: probe stat <path>")
		return 2
	}
	fi, err := os.Stat(args[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "stat %s: %v\n", args[0], err)
		return 1
	}
	sys, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		fmt.Fprintln(os.Stderr, "stat: no syscall.Stat_t")
		return 1
	}
	fmt.Printf("%d %d %04o\n", sys.Uid, sys.Gid, fi.Mode().Perm())
	return 0
}

// cmdEnviron prints the PID 1 environment entries whose name contains the given
// substring, reading /proc/1/environ so the driver sees the exec'd app's real
// environment (where an env-delivered secret lives), not this probe process's
// own. With no substring it prints every entry.
func cmdEnviron(args []string) int {
	match := ""
	if len(args) == 1 {
		match = args[0]
	}
	data, err := os.ReadFile("/proc/1/environ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "read /proc/1/environ: %v\n", err)
		return 1
	}
	for _, kv := range strings.Split(string(data), "\x00") {
		if kv == "" {
			continue
		}
		name := kv
		if i := strings.IndexByte(kv, '='); i >= 0 {
			name = kv[:i]
		}
		if match == "" || strings.Contains(name, match) {
			fmt.Println(kv)
		}
	}
	return 0
}

// cmdHas exits 0 if the path exists, 1 otherwise, for a plain presence check.
func cmdHas(args []string) int {
	if len(args) != 1 {
		fmt.Fprintln(os.Stderr, "usage: probe has <path>")
		return 2
	}
	if _, err := os.Stat(args[0]); err != nil {
		return 1
	}
	return 0
}

// cmdWaitfile blocks until a path exists or a timeout in seconds elapses,
// printing "ready" and exiting 0 on appearance or "timeout" and exiting 1
// otherwise. It is the harness's own waiter, so the driver can prove the volume
// manifest gates a reader without depending on busybox shell quirks.
func cmdWaitfile(args []string) int {
	if len(args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: probe waitfile <path> <timeout-seconds>")
		return 2
	}
	var secs int
	fmt.Sscanf(args[1], "%d", &secs)
	deadline := time.Now().Add(time.Duration(secs) * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(args[0]); err == nil {
			fmt.Println("ready")
			return 0
		}
		time.Sleep(100 * time.Millisecond)
	}
	fmt.Println("timeout")
	return 1
}
