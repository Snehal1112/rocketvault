package model

import "time"

// AuditLog is a single enriched audit event read from the database.
type AuditLog struct {
	ID           string
	UserID       string
	Action       string
	Details      string
	Timestamp    time.Time
	ResourceType string
	ResourceID   string
	IPAddress    string
	Outcome      string
	Source       string
	PrevHash     string
	Seq          *int64
}
