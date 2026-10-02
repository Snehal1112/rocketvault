package vaultapi

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCreateCertificate_SendsExportable(t *testing.T) {
	srv, probe := certWriteServer(t, keysForCertBody, http.StatusCreated, `{"id":"`+tlsCertID+`","name":"tls-cert"}`)
	c := newClientForTest(t, srv)
	_, err := c.CreateCertificate(context.Background(), "prod", CreateCertificateRequest{
		Name: "tls-cert", KeyName: "tls-key", ValidityDays: 30, Exportable: true,
	})
	require.NoError(t, err)
	require.Equal(t, true, probe.body["exportable"])
}

func TestCreateCertificate_OmitsExportableWhenFalse(t *testing.T) {
	srv, probe := certWriteServer(t, keysForCertBody, http.StatusCreated, `{"id":"`+tlsCertID+`","name":"tls-cert"}`)
	c := newClientForTest(t, srv)
	_, err := c.CreateCertificate(context.Background(), "prod", CreateCertificateRequest{Name: "tls-cert", KeyName: "tls-key", ValidityDays: 30})
	require.NoError(t, err)
	_, present := probe.body["exportable"]
	require.False(t, present, "an unset flag leaves the request body exactly as before")
}

func TestCreateKey_SendsExportable(t *testing.T) {
	srv, probe := vaultWriteServer(t, http.StatusCreated, `{"id":"`+rsaKeyID+`","name":"k","type":"RSA"}`)
	c := newClientForTest(t, srv)
	_, err := c.CreateKey(context.Background(), "prod", CreateKeyRequest{Name: "k", Type: "RSA", Bits: 2048, Exportable: true})
	require.NoError(t, err)
	require.Equal(t, true, probe.body["exportable"])
}
