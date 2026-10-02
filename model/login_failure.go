package model

import "time"

// LoginFailure counts consecutive failed logins for one username.
type LoginFailure struct {
	Username      string
	Failures      int
	LastFailureAt time.Time
}
