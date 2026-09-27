package cache

// The affinity cache file holds a client id -- and a client ip -- for every
// client the server has served (see SaveItemsToFile), so its permissions are
// part of what an operator is asked to trust. These tests pin them, and pin
// that tightening them did not break the save.

import (
	"encoding/gob"
	"os"
	"path/filepath"
	"testing"
)

// testValue is an exported-field stand-in for the cacheUrl the server stores:
// gob refuses a type with nothing to encode.
type testValue struct {
	Data string
}

func (v testValue) Size() int { return len(v.Data) }

func TestSaveItemsToFileIsOwnerOnly(t *testing.T) {
	gob.Register(testValue{}) // the cache stores an interface: gob needs the type

	const (
		key  = "client-id-tcp:abc"
		url  = "https://abc.ngrok.test"
		perm = 0600
	)

	path := filepath.Join(t.TempDir(), "affinity.cache")

	lru := NewLRUCache(1 << 20)
	lru.Set(key, testValue{Data: url})

	if err := lru.SaveItemsToFile(path); err != nil {
		t.Fatalf("SaveItemsToFile failed: %v", err)
	}

	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("the cache file was not written: %v", err)
	}
	if got := fi.Mode().Perm(); got != perm {
		t.Fatalf("the cache file is %o, want %o: it lists every client the server has served", got, perm)
	}

	// the save is still a save: what went in comes back out
	loaded := NewLRUCache(1 << 20)
	if err := loaded.LoadItemsFromFile(path); err != nil {
		t.Fatalf("LoadItemsFromFile failed: %v", err)
	}
	if v, ok := loaded.Get(key); !ok || v.(testValue).Data != url {
		t.Fatalf("the cache did not survive the round trip: got %v (present: %t)", v, ok)
	}

	// A file written by an older version keeps the mode it was created with --
	// the mode passed to OpenFile applies only at creation -- so the save has to
	// tighten it every time, not just the first time.
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatalf("failed to loosen the file for the test: %v", err)
	}
	if err := lru.SaveItemsToFile(path); err != nil {
		t.Fatalf("SaveItemsToFile failed on an existing file: %v", err)
	}
	if fi, err = os.Stat(path); err != nil {
		t.Fatalf("the cache file went missing: %v", err)
	}
	if got := fi.Mode().Perm(); got != perm {
		t.Fatalf("an existing cache file stayed %o, want %o: the save must tighten it", got, perm)
	}
}
