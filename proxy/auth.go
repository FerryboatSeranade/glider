package proxy

import "strings"

// ParseUsersParam parses "user:pass,user2:pass2" into a user map.
func ParseUsersParam(raw string) map[string]UserEntry {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}

	users := make(map[string]UserEntry)
	for _, entry := range strings.Split(raw, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}

		user, pass, ok := strings.Cut(entry, ":")
		if !ok || user == "" {
			continue
		}
		users[user] = UserEntry{Password: pass, Enabled: true}
	}

	if len(users) == 0 {
		return nil
	}
	return users
}
