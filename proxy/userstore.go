package proxy

import (
	"sync/atomic"
)

// UserStore keeps a thread-safe snapshot of users for auth checks.
type UserStore struct {
	v atomic.Value // stores map[string]string
}

// NewUserStore returns a new user store.
func NewUserStore() *UserStore {
	s := &UserStore{}
	s.Set(nil)
	return s
}

// Set replaces the current users map.
func (s *UserStore) Set(users map[string]string) {
	cpy := make(map[string]string)
	for k, v := range users {
		cpy[k] = v
	}
	s.v.Store(cpy)
}

// Users returns a copy of current users.
func (s *UserStore) Users() map[string]string {
	v := s.v.Load()
	if v == nil {
		return nil
	}
	current := v.(map[string]string)
	out := make(map[string]string, len(current))
	for k, val := range current {
		out[k] = val
	}
	return out
}

// HasUsers returns true when any user is configured.
func (s *UserStore) HasUsers() bool {
	v := s.v.Load()
	if v == nil {
		return false
	}
	return len(v.(map[string]string)) > 0
}

// Validate returns true when the provided user/password matches.
func (s *UserStore) Validate(user, pass string) bool {
	v := s.v.Load()
	if v == nil {
		return false
	}
	current := v.(map[string]string)
	expected, ok := current[user]
	if !ok {
		return false
	}
	return expected == pass
}

// DefaultUserStore is the shared store for dynamic auth.
var DefaultUserStore = NewUserStore()
