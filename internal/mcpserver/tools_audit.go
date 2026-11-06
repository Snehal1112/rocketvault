package mcpserver

import (
	"context"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"rocketvault/internal/vaultapi"
)

type queryAuditLogArgs struct {
	From         string `json:"from,omitempty" jsonschema:"only entries at or after this RFC3339 timestamp"`
	To           string `json:"to,omitempty" jsonschema:"only entries at or before this RFC3339 timestamp"`
	UserID       string `json:"user_id,omitempty" jsonschema:"only entries for this principal id"`
	Action       string `json:"action,omitempty" jsonschema:"only entries for this action, such as secret.read"`
	Outcome      string `json:"outcome,omitempty" jsonschema:"only entries with this outcome: success or failure"`
	ResourceType string `json:"resource_type,omitempty" jsonschema:"only entries for this resource type, such as secret"`
	ResourceID   string `json:"resource_id,omitempty" jsonschema:"only entries for this resource id"`
	Source       string `json:"source,omitempty" jsonschema:"only entries from this source: api, cli or system"`
	Limit        int    `json:"limit,omitempty" jsonschema:"maximum number of entries to return; capped by the server"`
}

// auditEntryResult is one audit record.
//
// Details is wrapped: it is assembled from user-supplied context, making it
// attacker-influenceable and a prime prompt-injection vector.
type auditEntryResult struct {
	ID           string    `json:"id"`
	Timestamp    string    `json:"timestamp,omitempty"`
	UserID       string    `json:"user_id,omitempty"`
	Action       string    `json:"action"`
	Outcome      string    `json:"outcome,omitempty"`
	ResourceType string    `json:"resource_type,omitempty"`
	ResourceID   string    `json:"resource_id,omitempty"`
	Source       string    `json:"source,omitempty"`
	IPAddress    string    `json:"ip_address,omitempty"`
	Details      Untrusted `json:"details,omitempty"`
}

type queryAuditLogResult struct {
	Entries []auditEntryResult `json:"entries"`
	Total   int                `json:"total"`
	// IntegrityOK reports whether the audit log's hash chain verified.
	IntegrityOK bool `json:"integrity_ok"`
	// IntegrityBreakSeq is the seq of the first broken row, when known.
	IntegrityBreakSeq *int64 `json:"integrity_break_seq,omitempty"`
	// IntegrityBreakReason is "gap" or "hash_mismatch" when the chain failed.
	IntegrityBreakReason string `json:"integrity_break_reason,omitempty"`
	// IntegrityWarning is set only when the chain failed. Tampering is the
	// single most important thing this tool can report, so it is stated
	// rather than left as a boolean the caller might not read.
	IntegrityWarning string `json:"integrity_warning,omitempty"`
	Truncated        bool   `json:"truncated"`
	Note             string `json:"note,omitempty"`
}

// registerAuditReadTools adds the read-tier audit tools.
func registerAuditReadTools(s *Server) {
	registerIf(s, TierRead, "query_audit_log",
		"Query the audit log, filtering by time, principal, action, outcome or resource. "+
			"Requires the global admin role: no per-vault role assignment grants access to audit logs.",
		Annotations{ReadOnly: true, Idempotent: true}, s.handleQueryAuditLog)
}

func (s *Server) handleQueryAuditLog(ctx context.Context, _ *mcp.CallToolRequest, args queryAuditLogArgs) (*mcp.CallToolResult, queryAuditLogResult, error) {
	limit := s.effectiveLimit(args.Limit)

	page, err := s.client.QueryAuditLogs(ctx, vaultapi.AuditFilter{
		From:         args.From,
		To:           args.To,
		UserID:       args.UserID,
		Action:       args.Action,
		Outcome:      args.Outcome,
		ResourceType: args.ResourceType,
		ResourceID:   args.ResourceID,
		Source:       args.Source,
		Limit:        limit,
	})
	if err != nil {
		// vaultapi's hint already names the global admin requirement for this
		// route, so it is forwarded rather than restated.
		return errorResult("could not query the audit log: %s", err), queryAuditLogResult{}, nil
	}

	entries := make([]auditEntryResult, 0, len(page.Entries))
	for _, entry := range page.Entries {
		entries = append(entries, auditEntryResult{
			ID:           entry.ID,
			Timestamp:    entry.Timestamp,
			UserID:       entry.UserID,
			Action:       entry.Action,
			Outcome:      entry.Outcome,
			ResourceType: entry.ResourceType,
			ResourceID:   entry.ResourceID,
			Source:       entry.Source,
			IPAddress:    entry.IPAddress,
			Details:      Wrap(entry.Details),
		})
	}

	result := queryAuditLogResult{
		Entries:              entries,
		Total:                page.Total,
		IntegrityOK:          page.IntegrityOK,
		IntegrityBreakSeq:    page.IntegrityBreakSeq,
		IntegrityBreakReason: page.IntegrityBreakReason,
		Truncated:            page.Truncated,
		Note:                 truncationNote(page.Truncated, limit),
	}
	if !page.IntegrityOK {
		result.IntegrityWarning = "The audit log's hash chain did not verify. " +
			"Entries may have been altered or removed. Investigate before relying on this data."
	}
	return nil, result, nil
}
