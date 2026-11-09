//go:build !windows

package elevated

import "context"

func Elevated() bool                                                  { return false }
func Open(context.Context, string, uint32, uint64) (*Session, error)  { return nil, ErrIdentity }
func (s *Session) service(context.Context, map[string]any, any) error { return ErrIdentity }
