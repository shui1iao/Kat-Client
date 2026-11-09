// Package userio preserves the initiating medium user's file-access boundary.
// It is not a sandbox: privileged OS/journal code must never accept user paths.
package userio

import (
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync/atomic"
)

var required atomic.Bool
var ErrMedium = errors.New("authenticated medium file token required")

// RequireMedium is called by the elevated fixed-role entry before any user I/O.
// It is monotonic for this process; only InstallMedium can satisfy it.
func RequireMedium()                     { required.Store(true) }
func Required() bool                     { return required.Load() }
func Open(name string) (*os.File, error) { return OpenFile(name, os.O_RDONLY, 0) }
func Create(name string) (*os.File, error) {
	return OpenFile(name, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0666)
}
func ReadFile(name string) ([]byte, error) {
	if !Required() {
		return os.ReadFile(name)
	}
	f, e := Open(name)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	return io.ReadAll(f)
}
func WriteFile(name string, b []byte, mode os.FileMode) error {
	if !Required() {
		return os.WriteFile(name, b, mode)
	}
	f, e := OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if e != nil {
		return e
	}
	n, e := f.Write(b)
	if e == nil && n != len(b) {
		e = io.ErrShortWrite
	}
	ce := f.Close()
	if e != nil {
		return e
	}
	return ce
}
func CreateTemp(dir, pattern string) (*os.File, error) {
	if !Required() {
		return os.CreateTemp(dir, pattern)
	}
	if dir == "" {
		dir = os.TempDir()
	}
	if strings.ContainsAny(pattern, `/\`) {
		return nil, &os.PathError{Op: "createtemp", Path: pattern, Err: os.ErrInvalid}
	}
	before, after := pattern, ""
	if i := strings.LastIndexByte(pattern, '*'); i >= 0 {
		before, after = pattern[:i], pattern[i+1:]
	}
	for i := 0; i < 10000; i++ {
		var b [12]byte
		if _, e := rand.Read(b[:]); e != nil {
			return nil, e
		}
		name := filepath.Join(dir, before+hex.EncodeToString(b[:])+after)
		f, e := OpenFile(name, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600)
		if os.IsExist(e) {
			continue
		}
		return f, e
	}
	return nil, &os.PathError{Op: "createtemp", Path: dir, Err: os.ErrExist}
}
func MkdirAll(path string, mode os.FileMode) error {
	if !Required() {
		return os.MkdirAll(path, mode)
	}
	st, e := Stat(path)
	if e == nil {
		if st.IsDir() {
			return nil
		}
		return &os.PathError{Op: "mkdir", Path: path, Err: os.ErrExist}
	}
	parent := filepath.Dir(filepath.Clean(path))
	if parent != path && parent != "." {
		if e := MkdirAll(parent, mode); e != nil {
			return e
		}
	}
	if e = Mkdir(path, mode); e != nil {
		if st, se := Stat(path); se == nil && st.IsDir() {
			return nil
		}
		return e
	}
	return nil
}

type entry struct {
	os.DirEntry
	path string
}

func (e entry) Info() (os.FileInfo, error) { return Lstat(e.path) }
func ReadDir(path string) ([]os.DirEntry, error) {
	if !Required() {
		return os.ReadDir(path)
	}
	f, e := OpenFile(path, os.O_RDONLY, 0)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	ds, e := f.ReadDir(-1)
	out := make([]os.DirEntry, len(ds))
	for i, d := range ds {
		out[i] = entry{d, filepath.Join(path, d.Name())}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name() < out[j].Name() })
	return out, e
}
func WalkDir(root string, fn fs.WalkDirFunc) error {
	if !Required() {
		return filepath.WalkDir(root, fn)
	}
	st, e := Lstat(root)
	if e != nil {
		return fn(root, nil, e)
	}
	var walk func(string, fs.DirEntry) error
	walk = func(p string, d fs.DirEntry) error {
		e := fn(p, d, nil)
		if e != nil {
			if e == fs.SkipDir && d.IsDir() {
				return nil
			}
			return e
		}
		if !d.IsDir() {
			return nil
		}
		ds, e := ReadDir(p)
		if e != nil {
			e = fn(p, d, e)
			if e == fs.SkipDir {
				return nil
			}
			return e
		}
		for _, c := range ds {
			if e := walk(filepath.Join(p, c.Name()), c); e != nil {
				return e
			}
		}
		return nil
	}
	e = walk(root, fs.FileInfoToDirEntry(st))
	if e == fs.SkipDir || e == fs.SkipAll {
		return nil
	}
	return e
}
func LoadX509KeyPair(cert, key string) (tls.Certificate, error) {
	a, e := ReadFile(cert)
	if e != nil {
		return tls.Certificate{}, e
	}
	b, e := ReadFile(key)
	if e != nil {
		return tls.Certificate{}, e
	}
	return tls.X509KeyPair(a, b)
}
