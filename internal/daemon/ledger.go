// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 techgaud

package daemon

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/tagwright/berm/internal/delivery"
)

// ledgerVersion is the on-disk ledger schema version, bumped when the record
// shape changes so a reader can refuse a shape it does not understand.
const ledgerVersion = 1

// HashSource is the one seam the ledger needs to read the CURRENT ciphertext
// hash of a source at rest, so it can compare it to the hash recorded at the
// last injection and report drift. delivery.Opener satisfies it. The ciphertext
// is encrypted, so a hash leaks no value.
type HashSource interface {
	SourceCipherHash(source string) (string, error)
}

// SourceInjection is one source's ciphertext hash as it stood when it was last
// injected into a container, plus when. The hash is of the ciphertext at rest,
// never a secret value, which is the whole reason the ledger MAY persist to a
// small non-secret file.
type SourceInjection struct {
	CipherHash string    `json:"cipher_hash"`
	InjectedAt time.Time `json:"injected_at"`
}

// ContainerRecord is the last-applied injection state for one container: which
// service identity and mechanism it resolved to, and the per-source ciphertext
// hash of everything last delivered to it. It holds names, hashes, and
// timestamps only, never a secret value.
type ContainerRecord struct {
	Service   string                     `json:"service"`
	Mechanism string                     `json:"mechanism"`
	Sources   map[string]SourceInjection `json:"sources"`
	UpdatedAt time.Time                  `json:"updated_at"`
}

// Ledger is the staleness ledger: a per-container, per-source record of the
// ciphertext hash last injected, so `berm stale` and the beacon digest can
// report which containers hold a source that changed since their last
// injection. It is the minimal state the architecture allows (last-applied spec
// plus the hash ledger), and it persists to a small non-secret JSON file so the
// stale query survives a daemon restart. It is safe for concurrent use.
type Ledger struct {
	mu      sync.Mutex
	path    string
	records map[string]ContainerRecord
}

// ledgerFile is the on-disk shape.
type ledgerFile struct {
	Version    int                        `json:"version"`
	Containers map[string]ContainerRecord `json:"containers"`
}

// NewLedger returns an empty ledger that persists to path. Nothing is read from
// disk. Use LoadLedger to reload an existing ledger.
func NewLedger(path string) *Ledger {
	return &Ledger{path: path, records: map[string]ContainerRecord{}}
}

// LoadLedger reads the ledger at path, or returns an empty ledger bound to that
// path if the file does not exist yet (a first run). A present but corrupt or
// wrong-version file is an error: the daemon must not silently start with a
// misread staleness history. This is the entrypoint `berm stale` (a later
// chunk) calls to read the ledger from a fresh process.
func LoadLedger(path string) (*Ledger, error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return NewLedger(path), nil
	}
	if err != nil {
		return nil, fmt.Errorf("daemon: read ledger %s: %w", path, err)
	}
	var lf ledgerFile
	if err := json.Unmarshal(data, &lf); err != nil {
		return nil, fmt.Errorf("daemon: parse ledger %s: %w", path, err)
	}
	if lf.Version != ledgerVersion {
		return nil, fmt.Errorf("daemon: ledger %s has version %d, want %d", path, lf.Version, ledgerVersion)
	}
	if lf.Containers == nil {
		lf.Containers = map[string]ContainerRecord{}
	}
	return &Ledger{path: path, records: lf.Containers}, nil
}

// RecordManifest records an injection from a delivered manifest: the container,
// its service and mechanism, and the ciphertext hash of every source the
// manifest names (across files, renders, and env). It records names, hashes,
// and the timestamp only, never a value. It then persists best-effort; a
// persistence error is returned so the caller can alert, but the in-memory
// record is already updated.
func (l *Ledger) RecordManifest(m *delivery.Manifest, now time.Time) error {
	if m == nil || m.Container == "" {
		return fmt.Errorf("daemon: cannot record an injection with no container id")
	}
	sources := map[string]SourceInjection{}
	add := func(source, hash string) {
		if source == "" {
			return
		}
		sources[source] = SourceInjection{CipherHash: hash, InjectedAt: now.UTC()}
	}
	for _, f := range m.Files {
		add(f.Source, f.CipherHash)
	}
	for _, r := range m.Renders {
		add(r.Source, r.CipherHash)
	}
	for _, e := range m.Env {
		add(e.Source, e.CipherHash)
	}

	l.mu.Lock()
	l.records[m.Container] = ContainerRecord{
		Service:   m.Service,
		Mechanism: m.Mechanism,
		Sources:   sources,
		UpdatedAt: now.UTC(),
	}
	l.mu.Unlock()

	return l.save()
}

// Forget drops a container's record, for a destroyed container. It persists the
// removal. A container the ledger does not know is a no-op.
func (l *Ledger) Forget(containerID string) error {
	l.mu.Lock()
	_, ok := l.records[containerID]
	if ok {
		delete(l.records, containerID)
	}
	l.mu.Unlock()
	if !ok {
		return nil
	}
	return l.save()
}

// Record returns a copy of one container's record and whether it is present.
func (l *Ledger) Record(containerID string) (ContainerRecord, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	r, ok := l.records[containerID]
	if !ok {
		return ContainerRecord{}, false
	}
	return copyRecord(r), true
}

// Drift is one source whose ciphertext changed since it was last injected into
// a container, the unit `berm stale` reports. A missing source (deleted since
// injection) is reported with an empty CurrentHash and Missing set, so a
// deleted source surfaces as loudly as a changed one.
type Drift struct {
	Container    string
	Service      string
	Source       string
	InjectedHash string
	CurrentHash  string
	InjectedAt   time.Time
	Missing      bool
}

// Drift compares every recorded injected hash to the current ciphertext hash of
// its source and returns the sources that changed (or vanished) since their last
// injection. It is the library query `berm stale` (a later chunk) calls. It
// never decrypts and never surfaces a value: it compares ciphertext hashes only.
// Results are sorted by container then source for a stable report.
func (l *Ledger) Drift(hs HashSource) ([]Drift, error) {
	l.mu.Lock()
	snapshot := make(map[string]ContainerRecord, len(l.records))
	for k, v := range l.records {
		snapshot[k] = copyRecord(v)
	}
	l.mu.Unlock()

	// Cache current hashes across containers so a shared source is hashed once.
	current := map[string]string{}
	currentErr := map[string]error{}
	hashNow := func(source string) (string, error) {
		if h, ok := current[source]; ok {
			return h, nil
		}
		if e, ok := currentErr[source]; ok {
			return "", e
		}
		h, err := hs.SourceCipherHash(source)
		if err != nil {
			currentErr[source] = err
			return "", err
		}
		current[source] = h
		return h, nil
	}

	var out []Drift
	for cid, rec := range snapshot {
		for source, inj := range rec.Sources {
			cur, err := hashNow(source)
			if err != nil {
				out = append(out, Drift{
					Container: cid, Service: rec.Service, Source: source,
					InjectedHash: inj.CipherHash, CurrentHash: "", InjectedAt: inj.InjectedAt,
					Missing: true,
				})
				continue
			}
			if cur != inj.CipherHash {
				out = append(out, Drift{
					Container: cid, Service: rec.Service, Source: source,
					InjectedHash: inj.CipherHash, CurrentHash: cur, InjectedAt: inj.InjectedAt,
				})
			}
		}
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].Container != out[j].Container {
			return out[i].Container < out[j].Container
		}
		return out[i].Source < out[j].Source
	})
	return out, nil
}

// save writes the ledger atomically (temp-then-rename in the same directory) so
// a reader never observes a partial file and a crash mid-write never corrupts
// the history. The caller holds no lock: save takes the lock to snapshot.
func (l *Ledger) save() error {
	if l.path == "" {
		return nil
	}
	l.mu.Lock()
	lf := ledgerFile{Version: ledgerVersion, Containers: l.records}
	data, err := json.MarshalIndent(lf, "", "  ")
	l.mu.Unlock()
	if err != nil {
		return fmt.Errorf("daemon: marshal ledger: %w", err)
	}

	dir := filepath.Dir(l.path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("daemon: create ledger dir %s: %w", dir, err)
	}
	tmp, err := os.CreateTemp(dir, ".berm-ledger-*.tmp")
	if err != nil {
		return fmt.Errorf("daemon: create ledger temp: %w", err)
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return fmt.Errorf("daemon: write ledger temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("daemon: close ledger temp: %w", err)
	}
	if err := os.Rename(tmpName, l.path); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("daemon: publish ledger: %w", err)
	}
	return nil
}

// copyRecord deep-copies a record so a returned or snapshotted value shares no
// map with the live ledger.
func copyRecord(r ContainerRecord) ContainerRecord {
	sources := make(map[string]SourceInjection, len(r.Sources))
	for k, v := range r.Sources {
		sources[k] = v
	}
	r.Sources = sources
	return r
}
