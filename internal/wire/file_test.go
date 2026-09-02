// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 techgaud

package wire

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// tmpfsTestDir returns a writable directory and whether the tmpfs guarantee can
// be enforced there. It prefers a fresh subdir of /dev/shm (a real tmpfs in a
// container), so the tmpfs-enforcement path is actually exercised. Where no
// tmpfs is available it falls back to a normal temp dir with enforcement off and
// says so, per the build note: production requires tmpfs, CI may lack it.
func tmpfsTestDir(t *testing.T) (dir string, requireTmpfs bool) {
	t.Helper()
	if d, err := os.MkdirTemp("/dev/shm", "berm-wire-*"); err == nil {
		t.Cleanup(func() { os.RemoveAll(d) })
		return d, true
	}
	t.Log("NOTE: /dev/shm unavailable; falling back to a non-tmpfs temp dir with the tmpfs guarantee relaxed. Production requires tmpfs.")
	return t.TempDir(), false
}

func TestWriteTmpfsFileBytes(t *testing.T) {
	dir, requireTmpfs := tmpfsTestDir(t)
	path := filepath.Join(dir, "sub", "secret")
	want := []byte("s3cr3t-value\nwith bytes\x00\xff")

	if err := WriteBytesFile(path, "1000:1000", "0400", requireTmpfs, want); err != nil {
		t.Fatalf("WriteBytesFile: %v", err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("content = %q, want %q", got, want)
	}

	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if fi.Mode().Perm() != 0o400 {
		t.Errorf("mode = %o, want 0400", fi.Mode().Perm())
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		if st.Uid != 1000 || st.Gid != 1000 {
			t.Errorf("owner = %d:%d, want 1000:1000 (running as uid %d)", st.Uid, st.Gid, os.Getuid())
		}
	}
}

func TestWriteTmpfsFileStreamProduce(t *testing.T) {
	dir, requireTmpfs := tmpfsTestDir(t)
	path := filepath.Join(dir, "streamed")
	want := []byte("streamed straight to the fd")

	n, err := WriteTmpfsFile(path, "0:0", "0644", requireTmpfs, func(w io.Writer) (int64, error) {
		m, e := w.Write(want)
		return int64(m), e
	})
	if err != nil {
		t.Fatalf("WriteTmpfsFile: %v", err)
	}
	if int(n) != len(want) {
		t.Errorf("n = %d, want %d", n, len(want))
	}
	got, _ := os.ReadFile(path)
	if !bytes.Equal(got, want) {
		t.Errorf("content = %q, want %q", got, want)
	}
}

func TestWriteTmpfsFileNoPartialOnProduceError(t *testing.T) {
	dir, requireTmpfs := tmpfsTestDir(t)
	path := filepath.Join(dir, "never")

	_, err := WriteTmpfsFile(path, "0:0", "0400", requireTmpfs, func(w io.Writer) (int64, error) {
		w.Write([]byte("partial"))
		return 7, io.ErrUnexpectedEOF
	})
	if err == nil {
		t.Fatal("expected an error from a failing produce")
	}
	if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
		t.Errorf("a failed produce must publish nothing, but %q exists", path)
	}
	// The temp file must be cleaned up too.
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		t.Errorf("leftover after failed write: %s", e.Name())
	}
}

func TestRequireTmpfsRefusesPersistentDir(t *testing.T) {
	// t.TempDir is on the CI overlay/ext4, not tmpfs, so enforcement must refuse.
	// If it happens to be tmpfs (rare), skip rather than assert the opposite.
	dir := t.TempDir()
	if isTmpfs(t, dir) {
		t.Skip("t.TempDir is tmpfs here; nothing to refuse")
	}
	err := WriteBytesFile(filepath.Join(dir, "x"), "0:0", "0400", true, []byte("nope"))
	if err == nil {
		t.Fatal("expected refusal writing a secret to a non-tmpfs dir with requireTmpfs=true")
	}
}

func isTmpfs(t *testing.T, dir string) bool {
	t.Helper()
	var st syscall.Statfs_t
	if err := syscall.Statfs(dir, &st); err != nil {
		return false
	}
	const tmpfsMagic = 0x01021994
	const ramfsMagic = 0x858458f6
	return uint64(st.Type) == tmpfsMagic || uint64(st.Type) == ramfsMagic
}

func TestParseOwner(t *testing.T) {
	cases := []struct {
		in       string
		uid, gid int
		wantErr  bool
	}{
		{"1000:1000", 1000, 1000, false},
		{"0:0", 0, 0, false},
		{"1000", 1000, gidUnchanged, false},
		{"", 0, 0, true},
		{"root:root", 0, 0, true},
		{"1000:grp", 0, 0, true},
	}
	for _, c := range cases {
		uid, gid, err := parseOwner(c.in)
		if c.wantErr {
			if err == nil {
				t.Errorf("parseOwner(%q) expected error", c.in)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseOwner(%q): %v", c.in, err)
			continue
		}
		if uid != c.uid || gid != c.gid {
			t.Errorf("parseOwner(%q) = %d:%d, want %d:%d", c.in, uid, gid, c.uid, c.gid)
		}
	}
}

func TestParseMode(t *testing.T) {
	m, err := parseMode("0400")
	if err != nil || m != 0o400 {
		t.Errorf("parseMode(0400) = %o, %v", m, err)
	}
	m, err = parseMode("440")
	if err != nil || m != 0o440 {
		t.Errorf("parseMode(440) = %o, %v", m, err)
	}
	if _, err := parseMode("nope"); err == nil {
		t.Error("parseMode(nope) expected error")
	}
}
