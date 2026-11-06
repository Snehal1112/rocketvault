package vaultapi

import (
	"context"
	"net/http"
	"net/url"
	"strconv"
)

// auditLogsPath is the audit query route. It is global, not vault-scoped.
const auditLogsPath = "/api/v1/audit/logs"

// AuditFilter constrains an audit query. Empty fields are omitted, matching
// parseAuditFilter's nil-means-unfiltered contract.
type AuditFilter struct {
	From         string // RFC3339.
	To           string // RFC3339.
	UserID       string
	Action       string
	Outcome      string
	ResourceType string
	ResourceID   string
	Source       string // "api" | "cli" | "system".
	Limit        int
}

// values renders the filter as query parameters, omitting empty fields.
func (f AuditFilter) values() url.Values {
	q := url.Values{}
	for key, value := range map[string]string{
		"from":          f.From,
		"to":            f.To,
		"user_id":       f.UserID,
		"action":        f.Action,
		"outcome":       f.Outcome,
		"resource_type": f.ResourceType,
		"resource_id":   f.ResourceID,
		"source":        f.Source,
	} {
		if value != "" {
			q.Set(key, value)
		}
	}
	if f.Limit > 0 {
		q.Set("limit", strconv.Itoa(f.Limit))
	}
	return q
}

// AuditEntry is one audit log record.
//
// Details is free text assembled from user-supplied context, so it is
// attacker-influenceable and a prime prompt-injection vector. This layer
// passes it through verbatim; wrapping it as untrusted content before a model
// sees it belongs to the MCP layer.
type AuditEntry struct {
	ID           string `json:"id"`
	UserID       string `json:"user_id,omitempty"`
	Action       string `json:"action"`
	Details      string `json:"details,omitempty"`
	ResourceType string `json:"resource_type,omitempty"`
	ResourceID   string `json:"resource_id,omitempty"`
	IPAddress    string `json:"ip_address,omitempty"`
	Outcome      string `json:"outcome,omitempty"`
	Source       string `json:"source,omitempty"`
	Timestamp    string `json:"timestamp,omitempty"`
}

// AuditPage is one page of audit results.
type AuditPage struct {
	Entries []AuditEntry `json:"entries"`
	// Total is the server's count before client-side truncation.
	Total int `json:"total"`
	// IntegrityOK reports whether the hash chain verified. A false value
	// means the log may have been tampered with and must reach the caller.
	IntegrityOK bool `json:"integrity_ok"`
	// IntegrityBreakSeq is the seq of the first broken row, when known.
	IntegrityBreakSeq *int64 `json:"integrity_break_seq,omitempty"`
	// IntegrityBreakReason is "gap" or "hash_mismatch" when the chain failed.
	IntegrityBreakReason string `json:"integrity_break_reason,omitempty"`
	// Truncated reports that Entries was cut to the requested limit.
	Truncated bool `json:"truncated"`
}

// QueryAuditLogs returns a page of audit records.
//
// This route requires the global admin role (api/audit.go:66), which no vault
// role assignment grants. A least-privileged service account will receive 403
// here, and that is expected rather than a defect.
func (c *Client) QueryAuditLogs(ctx context.Context, filter AuditFilter) (*AuditPage, error) {
	path := auditLogsPath
	if encoded := filter.values().Encode(); encoded != "" {
		path += "?" + encoded
	}

	var response struct {
		Logs        []AuditEntry `json:"logs"`
		Total       int          `json:"total"`
		IntegrityOK bool         `json:"integrity_ok"`

		IntegrityBreakSeq    *int64 `json:"integrity_break_seq"`
		IntegrityBreakReason string `json:"integrity_break_reason"`
	}
	if err := c.Do(ctx, http.MethodGet, path, nil, &response); err != nil {
		return nil, err
	}

	entries := response.Logs
	truncated := filter.Limit > 0 && len(entries) > filter.Limit
	if truncated {
		entries = entries[:filter.Limit]
	}

	return &AuditPage{
		Entries:     entries,
		Total:       response.Total,
		IntegrityOK: response.IntegrityOK,

		IntegrityBreakSeq:    response.IntegrityBreakSeq,
		IntegrityBreakReason: response.IntegrityBreakReason,
		Truncated:            truncated,
	}, nil
}
