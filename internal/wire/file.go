// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 the berm authors

package wire

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// gidUnchanged is the fchown gid sentinel that leaves a file's group unchanged.
// It is used when an owner names a uid with no gid, so a bare "1000" sets the
// user and leaves the group as the process default rather than guessing a gid.
const gidUnchanged = -1

// dirMode is the mode for parent directories the writer creates under a tmpfs
// root. The secret is protected by its own file mode; the directory is
// traversable so an app process under the owner uid can reach the file.
const dirMode os.FileMode = 0o755

// WriteTmpfsFile writes a single secret file at path, on tmpfs, with the given
// numeric owner and octal mode, sourcing its content from produce.
//
// produce is handed the destination file and writes the plaintext to it,
// returning the byte count. This one seam serves both delivery paths: the
// daemon-side writer passes a produce that streams the backend's decrypt output
// straight into the file descriptor (off Go's heap for a whole binary payload),
// and the client-side apply passes a produce that copies the already-decrypted
// bytes it received over the socket. Neither path writes plaintext anywhere but
// this one tmpfs file.
//
// The write is temp-then-rename within the destination's own directory, so a
// reader never observes a partial file and a failed decrypt leaves nothing
// published. When requireTmpfs is set the destination directory must be a tmpfs
// or ramfs mount or the write is refused before any plaintext is produced,
// enforcing the no-plaintext-on-persistent-disk half of the security contract.
// Production always sets requireTmpfs. A test on a CI container without a tmpfs
// mount may clear it, at the cost of that one guarantee, and must say so.
func WriteTmpfsFile(path, owner, mode string, requireTmpfs bool, produce func(io.Writer) (int64, error)) (int64, error) {
	uid, gid, err := parseOwner(owner)
	if err != nil {
		return 0, err
	}
	fileMode, err := parseMode(mode)
	if err != nil {
		return 0, err
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, dirMode); err != nil {
		return 0, fmt.Errorf("wire: create parent dir for %q: %w", path, err)
	}
	if requireTmpfs {
		if err := checkTmpfs(dir); err != nil {
			return 0, err
		}
	}

	tmp, err := os.CreateTemp(dir, ".berm-*.tmp")
	if err != nil {
		return 0, fmt.Errorf("wire: create temp for %q: %w", path, err)
	}
	tmpName := tmp.Name()
	// From here every early return must clean up the temp so a failed delivery
	// never leaves a plaintext fragment behind.
	published := false
	defer func() {
		if !published {
			tmp.Close()
			os.Remove(tmpName)
		}
	}()

	n, err := produce(tmp)
	if err != nil {
		return n, fmt.Errorf("wire: write content for %q: %w", path, err)
	}
	if err := tmp.Chmod(fileMode); err != nil {
		return n, fmt.Errorf("wire: chmod %q: %w", path, err)
	}
	if err := unix.Fchown(int(tmp.Fd()), uid, gid); err != nil {
		return n, fmt.Errorf("wire: chown %q to %s: %w", path, owner, err)
	}
	if err := tmp.Sync(); err != nil {
		return n, fmt.Errorf("wire: fsync %q: %w", path, err)
	}
	if err := tmp.Close(); err != nil {
		return n, fmt.Errorf("wire: close %q: %w", path, err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return n, fmt.Errorf("wire: publish %q: %w", path, err)
	}
	published = true
	return n, nil
}

// WriteBytesFile is the byte-slice convenience over WriteTmpfsFile, for content
// already in memory (a manifest, or a client applying decrypted bundle bytes).
func WriteBytesFile(path, owner, mode string, requireTmpfs bool, data []byte) error {
	_, err := WriteTmpfsFile(path, owner, mode, requireTmpfs, func(w io.Writer) (int64, error) {
		n, werr := w.Write(data)
		return int64(n), werr
	})
	return err
}

// parseOwner parses a numeric "uid" or "uid:gid" owner. A bare uid leaves the
// group unchanged. The grammar requires numeric ids only, so a non-numeric
// component is an error rather than a name lookup, keeping the writer free of
// any dependency on the container's user database.
func parseOwner(owner string) (uid, gid int, err error) {
	if owner == "" {
		return 0, 0, fmt.Errorf("wire: empty owner")
	}
	u, g, hasGid := strings.Cut(owner, ":")
	uid, err = strconv.Atoi(u)
	if err != nil {
		return 0, 0, fmt.Errorf("wire: owner uid %q is not numeric", u)
	}
	if !hasGid {
		return uid, gidUnchanged, nil
	}
	gid, err = strconv.Atoi(g)
	if err != nil {
		return 0, 0, fmt.Errorf("wire: owner gid %q is not numeric", g)
	}
	return uid, gid, nil
}

// parseMode parses an octal mode string such as "0400" or "440" into a
// FileMode, keeping only the permission bits.
func parseMode(mode string) (os.FileMode, error) {
	if mode == "" {
		return 0, fmt.Errorf("wire: empty mode")
	}
	v, err := strconv.ParseUint(mode, 8, 32)
	if err != nil {
		return 0, fmt.Errorf("wire: mode %q is not an octal string", mode)
	}
	return os.FileMode(v) & os.ModePerm, nil
}

// checkTmpfs confirms dir sits on a tmpfs or ramfs mount, the only backings
// where a secret file never touches persistent disk. Any other filesystem is
// refused. A statfs failure is refused too: the writer fails closed rather than
// write a secret to a filesystem it could not verify.
func checkTmpfs(dir string) error {
	var st unix.Statfs_t
	if err := unix.Statfs(dir, &st); err != nil {
		return fmt.Errorf("wire: statfs %q to verify tmpfs: %w", dir, err)
	}
	switch st.Type {
	case unix.TMPFS_MAGIC, unix.RAMFS_MAGIC:
		return nil
	default:
		return fmt.Errorf("wire: refusing to write secret to %q: filesystem 0x%x is not tmpfs or ramfs", dir, uint64(st.Type))
	}
}
