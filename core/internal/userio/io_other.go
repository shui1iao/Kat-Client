//go:build !windows

package userio

import "os"

func Check() error {
	if Required() {
		return ErrMedium
	}
	return nil
}
func OpenFile(p string, f int, m os.FileMode) (*os.File, error) {
	if e := Check(); e != nil {
		return nil, e
	}
	return os.OpenFile(p, f, m)
}
func Stat(p string) (os.FileInfo, error) {
	if e := Check(); e != nil {
		return nil, e
	}
	return os.Stat(p)
}
func Lstat(p string) (os.FileInfo, error) {
	if e := Check(); e != nil {
		return nil, e
	}
	return os.Lstat(p)
}
func Mkdir(p string, m os.FileMode) error {
	if e := Check(); e != nil {
		return e
	}
	return os.Mkdir(p, m)
}
func Remove(p string) error {
	if e := Check(); e != nil {
		return e
	}
	return os.Remove(p)
}
func RemoveAll(p string) error {
	if e := Check(); e != nil {
		return e
	}
	return os.RemoveAll(p)
}
func Rename(a, b string) error {
	if e := Check(); e != nil {
		return e
	}
	return os.Rename(a, b)
}
func Link(a, b string) error {
	if e := Check(); e != nil {
		return e
	}
	return os.Link(a, b)
}
func Chmod(p string, m os.FileMode) error {
	if e := Check(); e != nil {
		return e
	}
	return os.Chmod(p, m)
}
func OpenRoot(p string) (*os.Root, error) {
	if e := Check(); e != nil {
		return nil, e
	}
	return os.OpenRoot(p)
}
