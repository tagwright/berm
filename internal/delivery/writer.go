// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 the berm authors

package delivery

import (
	"context"
	"fmt"
	"io"
	"path/filepath"

	"github.com/tagwright/berm/internal/wire"
)

// WriteFile lands one resolved file delivery on tmpfs, decrypting via the
// backend straight into the destination file descriptor. This is the path the
// hook and volume mechanisms use, where the daemon writes into the target
// itself. A whole binary payload streams off Go's managed heap (WritePayload
// wires the sops pipe to the file). A single dotenv key necessarily buffers in
// the backend to parse the one value out, then streams that value to the file.
//
// requireTmpfs enforces the no-plaintext-on-persistent-disk contract and is
// always set in production. It streams temp-then-rename, so a failed decrypt
// publishes nothing.
func WriteFile(ctx context.Context, opener Opener, ft FileTarget, requireTmpfs bool) error {
	op, err := opener.OpenSource(ctx, ft.Source)
	if err != nil {
		return fmt.Errorf("delivery: open source %q for file %q: %w", ft.Source, ft.Name, err)
	}
	defer op.Close()

	produce := func(w io.Writer) (int64, error) {
		if ft.Whole {
			return op.WritePayload(w)
		}
		return op.WriteValue(w, ft.Key)
	}
	if _, err := wire.WriteTmpfsFile(ft.Path, ft.Owner, ft.Mode, requireTmpfs, produce); err != nil {
		return fmt.Errorf("delivery: write file %q: %w", ft.Name, err)
	}
	return nil
}

// WriteRender lands one whole-source render on tmpfs. berm.dotenv writes the
// whole default source as one KEY=VALUE dotenv file. berm.envdir writes one file
// per key under a directory, named for the key, the s6-overlay
// container_environment style. Both stream each value from the backend into the
// destination file descriptor.
func WriteRender(ctx context.Context, opener Opener, rt RenderTarget, requireTmpfs bool) error {
	op, err := opener.OpenSource(ctx, rt.Source)
	if err != nil {
		return fmt.Errorf("delivery: open source %q for render: %w", rt.Source, err)
	}
	defer op.Close()

	keys, err := op.Keys()
	if err != nil {
		return fmt.Errorf("delivery: list keys of %q for render: %w", rt.Source, err)
	}

	switch rt.Kind {
	case RenderDotenv:
		produce := func(w io.Writer) (int64, error) {
			var total int64
			for _, k := range keys {
				n, e := io.WriteString(w, k+"=")
				total += int64(n)
				if e != nil {
					return total, e
				}
				vn, e := op.WriteValue(w, k)
				total += vn
				if e != nil {
					return total, e
				}
				n, e = io.WriteString(w, "\n")
				total += int64(n)
				if e != nil {
					return total, e
				}
			}
			return total, nil
		}
		if _, err := wire.WriteTmpfsFile(rt.Path, rt.Owner, rt.Mode, requireTmpfs, produce); err != nil {
			return fmt.Errorf("delivery: write dotenv render: %w", err)
		}
		return nil

	case RenderEnvdir:
		for _, k := range keys {
			key := k
			dst := filepath.Join(rt.Path, key)
			produce := func(w io.Writer) (int64, error) {
				return op.WriteValue(w, key)
			}
			if _, err := wire.WriteTmpfsFile(dst, rt.Owner, rt.Mode, requireTmpfs, produce); err != nil {
				return fmt.Errorf("delivery: write envdir file %q: %w", key, err)
			}
		}
		return nil

	default:
		return fmt.Errorf("delivery: unknown render kind %q", rt.Kind)
	}
}
