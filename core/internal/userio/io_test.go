package userio

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestOrdinaryStorageIdentityAndAtomicNames(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "source")
	if e := WriteFile(p, []byte("accepted"), 0600); e != nil {
		t.Fatal(e)
	}
	a, e := Stat(p)
	if e != nil {
		t.Fatal(e)
	}
	f, e := Open(p)
	if e != nil {
		t.Fatal(e)
	}
	b, e := f.Stat()
	f.Close()
	if e != nil || !os.SameFile(a, b) {
		t.Fatal("file identity lost", e)
	}
	tmp, e := CreateTemp(dir, ".kat-write-*")
	if e != nil {
		t.Fatal(e)
	}
	if _, e = tmp.WriteString("next"); e != nil {
		t.Fatal(e)
	}
	tmp.Close()
	if e = Rename(tmp.Name(), p); e != nil {
		t.Fatal(e)
	}
	got, e := ReadFile(p)
	if e != nil || string(got) != "next" {
		t.Fatal(string(got), e)
	}
	root, e := OpenRoot(dir)
	if e != nil {
		t.Fatal(e)
	}
	defer root.Close()
	if e = root.RemoveAll("source"); e != nil {
		t.Fatal(e)
	}
}
func TestRequiredWithoutAuthenticatedTokenFailsClosed(t *testing.T) {
	if os.Getenv("KAT_TEST_USERIO_DENY") == "1" {
		RequireMedium()
		for _, fn := range []func() error{func() error { _, e := Open(os.Args[0]); return e }, func() error { _, e := Stat(os.Args[0]); return e }, func() error { return Mkdir(filepath.Join(os.TempDir(), "must-not-create-medium"), 0700) }, func() error { return Rename("a", "b") }} {
			if e := fn(); !errors.Is(e, ErrMedium) {
				t.Fatalf("missing-token operation did not fail closed: %v", e)
			}
		}
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestRequiredWithoutAuthenticatedTokenFailsClosed$")
	cmd.Env = append(os.Environ(), "KAT_TEST_USERIO_DENY=1")
	if b, e := cmd.CombinedOutput(); e != nil {
		t.Fatal(e, string(b))
	}
}
