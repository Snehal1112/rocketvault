package api

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"

	"rocketvault/internal/services/exportaudit"
)

// TestExportStatus_MapsEveryKind pins the HTTP status of every export
// failure kind, now that the classification lives in exportaudit.
func TestExportStatus_MapsEveryKind(t *testing.T) {
	for kind, want := range map[exportaudit.Kind]int{
		exportaudit.KindBadRequest:    http.StatusBadRequest,
		exportaudit.KindForbidden:     http.StatusForbidden,
		exportaudit.KindNotExportable: http.StatusForbidden,
		exportaudit.KindNotFound:      http.StatusNotFound,
		exportaudit.KindDisabled:      http.StatusConflict,
		exportaudit.KindInternal:      http.StatusInternalServerError,
	} {
		assert.Equal(t, want, exportStatus(kind), "kind %d", kind)
	}
}
