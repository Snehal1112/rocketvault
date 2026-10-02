package model

import "time"

// LoginFailure counts consecutive failed logins for one username.
// Username holds the hashed throttle key, never the raw attempted name.
type LoginFailure struct {
	Username      string
	Failures      int
	LastFailureAt time.Time
}
