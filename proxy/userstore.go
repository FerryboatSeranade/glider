package proxy

import (
	"sync/atomic"
	"time"
)

// UserEntry is a user auth record with optional expiration.
type UserEntry struct {
	Password  string
	Enabled   bool
	ExpiresAt *time.Time
}

// UserStore keeps a thread-safe snapshot of users for auth checks.
type UserStore struct {
	v atomic.Value // stores map[string]UserEntry
}

// NewUserStore returns a new user store.
func NewUserStore() *UserStore {
	s := &UserStore{}
	s.Set(nil)
	return s
}

// Set replaces the current users map.
func (s *UserStore) Set(users map[string]UserEntry) {
	cpy := make(map[string]UserEntry)
	for k, v := range users {
		entry := v
		if entry.ExpiresAt != nil {
			t := *entry.ExpiresAt
			entry.ExpiresAt = &t
		}
		cpy[k] = entry
	}
	s.v.Store(cpy)
}

// Users returns a copy of current users.
func (s *UserStore) Users() map[string]UserEntry {
	v := s.v.Load()
	if v == nil {
		return nil
	}
	current := v.(map[string]UserEntry)
	out := make(map[string]UserEntry, len(current))
	for k, val := range current {
		entry := val
		if entry.ExpiresAt != nil {
			t := *entry.ExpiresAt
			entry.ExpiresAt = &t
		}
		out[k] = entry
	}
	return out
}

// HasUsers returns true when any user is configured.
func (s *UserStore) HasUsers() bool {
	v := s.v.Load()
	if v == nil {
		return false
	}
	return len(v.(map[string]UserEntry)) > 0
}

// Validate returns true when the provided user/password matches and is active.
func (s *UserStore) Validate(user, pass string) bool {
	v := s.v.Load()
	if v == nil {
		return false
	}
	current := v.(map[string]UserEntry)
	entry, ok := current[user]
	if !ok {
		return false
	}
	if !entry.Enabled {
		return false
	}
	if entry.ExpiresAt != nil && !entry.ExpiresAt.IsZero() && time.Now().After(*entry.ExpiresAt) {
		return false
	}
	return entry.Password == pass
}

// DefaultUserStore is the shared store for dynamic auth.
var DefaultUserStore = NewUserStore()
