package vaultapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

const certListForVersions = `{"certificates":[{"id":"` + tlsCertID + `","name":"tls-cert"}]}`

func TestGetCertificateVersions_ResolvesAndDecodesWrapper(t *testing.T) {
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/api/v1/vaults/prod/certificates" {
			_, _ = w.Write([]byte(certListForVersions))
			return
		}
		_, _ = w.Write([]byte(`{"versions":[
			{"certificate_id":"` + tlsCertID + `","version":1,"current":false,"enabled":true,"created_at":"2026-08-01T00:00:00Z"},
			{"certificate_id":"` + tlsCertID + `","version":2,"current":true,"enabled":true,"created_at":"2026-09-01T00:00:00Z"}
		]}`))
	}))
	defer srv.Close()

	got, err := newClientForTest(t, srv).GetCertificateVersions(context.Background(), "prod", "tls-cert")
	require.NoError(t, err)
	require.Contains(t, paths, "/api/v1/vaults/prod/certificates/"+tlsCertID+"/versions")
	require.Len(t, got, 2)
	require.Equal(t, 2, got[1].Version)
	require.True(t, got[1].Current)
}

func TestRenewCertificate_PostsValidityAndDecodesVersion(t *testing.T) {
	var body map[string]any
	var renewPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodGet {
			_, _ = w.Write([]byte(certListForVersions))
			return
		}
		renewPath = r.URL.Path
		_ = json.NewDecoder(r.Body).Decode(&body)
		_, _ = w.Write([]byte(`{"certificate_id":"` + tlsCertID + `","version":3,"current":true,"enabled":true,
			"created_at":"2026-10-01T00:00:00Z","expires_at":"2027-10-01T00:00:00Z"}`))
	}))
	defer srv.Close()

	got, err := newClientForTest(t, srv).RenewCertificate(context.Background(), "prod", "tls-cert", 90)
	require.NoError(t, err)
	require.Equal(t, "/api/v1/vaults/prod/certificates/"+tlsCertID+"/renew", renewPath)
	require.Equal(t, float64(90), body["validity_days"])
	require.Equal(t, 3, got.Version)
	require.NotNil(t, got.ExpiresAt)
}

func TestRenewCertificate_OmitsValidityWhenZero(t *testing.T) {
	var body map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodGet {
			_, _ = w.Write([]byte(certListForVersions))
			return
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		_, _ = w.Write([]byte(`{"certificate_id":"` + tlsCertID + `","version":2,"current":true}`))
	}))
	defer srv.Close()

	_, err := newClientForTest(t, srv).RenewCertificate(context.Background(), "prod", "tls-cert", 0)
	require.NoError(t, err)
	require.NotContains(t, body, "validity_days", "zero means keep the current validity period")
}

func TestRenewCertificate_RequiresVaultAndName(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	client := newClientForTest(t, srv)

	_, err := client.RenewCertificate(context.Background(), "", "tls-cert", 30)
	require.ErrorContains(t, err, "vault is required")
	_, err = client.RenewCertificate(context.Background(), "prod", "", 30)
	require.ErrorContains(t, err, "name is required")
	_, err = client.RenewCertificate(context.Background(), "prod", "tls-cert", -1)
	require.ErrorContains(t, err, "validity_days")
}
