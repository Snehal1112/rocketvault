package api

import (
	"encoding/json"
	"net/http"
)

// setNoStore marks a response as uncacheable unless the handler chose its own
// Cache-Control value, as the public JWKS document does.
func setNoStore(w http.ResponseWriter) {
	if w.Header().Get("Cache-Control") == "" {
		w.Header().Set("Cache-Control", "no-store")
	}
}

// writeJSON writes v as a JSON response body with a 200 status.
//
// It replaces the Content-Type-set-then-encode pair that was repeated at
// roughly seventy-eight sites in this package, and with it the per-site
// //nolint:errcheck,gosec directive. The encode error is deliberately
// discarded, exactly as every call site already discarded it: the status line
// and headers are already on the wire by the time Encode can fail, so there is
// no way left to report the failure to the client.
func writeJSON[T any](w http.ResponseWriter, v T) {
	setNoStore(w)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v) //nolint:errcheck,gosec
}

// writeJSONStatus writes v as a JSON response body with an explicit status.
//
// The header must be set before WriteHeader, because WriteHeader commits the
// header map; a Content-Type set afterwards is silently dropped. That ordering
// is why this is a separate helper rather than a status argument on writeJSON.
func writeJSONStatus[T any](w http.ResponseWriter, status int, v T) {
	setNoStore(w)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v) //nolint:errcheck,gosec
}
