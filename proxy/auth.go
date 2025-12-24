package proxy

import "strings"

// ParseUsersParam parses "user:pass,user2:pass2" into a user map.
func ParseUsersParam(raw string) map[string]string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}

	users := make(map[string]string)
	for _, entry := range strings.Split(raw, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}

		user, pass, ok := strings.Cut(entry, ":")
		if !ok || user == "" {
			continue
		}
		users[user] = pass
	}

	if len(users) == 0 {
		return nil
	}
	return users
}
