package certificates

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	pkcs12 "software.sslmate.com/src/go-pkcs12"

	"rocketvault/common"
	"rocketvault/internal/crypto"
	"rocketvault/model"
)

// startOpenSSLServer runs `openssl s_server -Verify 1` trusting caPEM for
// client certificates and returns its address and the server certificate.
func startOpenSSLServer(t *testing.T, caPEM string) (string, *x509.Certificate) {
	t.Helper()
	openssl, err := exec.LookPath("openssl")
	if err != nil {
		t.Skip("openssl not found on PATH; the TLS end-to-end export test needs `openssl s_server`")
	}
	dir := t.TempDir()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: "127.0.0.1"},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	serverCert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	write := func(name string, block *pem.Block) string {
		p := filepath.Join(dir, name)
		require.NoError(t, os.WriteFile(p, pem.EncodeToMemory(block), 0o600))
		return p
	}
	certPath := write("server.pem", &pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPath := write("server.key", &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	caPath := filepath.Join(dir, "ca.pem")
	require.NoError(t, os.WriteFile(caPath, []byte(caPEM), 0o600))

	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := l.Addr().String()
	require.NoError(t, l.Close())

	cmd := exec.Command(openssl, "s_server", "-accept", addr, "-cert", certPath, "-key", keyPath,
		"-CAfile", caPath, "-Verify", "1", "-verify_return_error", "-www", "-quiet")
	require.NoError(t, cmd.Start())
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })

	deadline := time.Now().Add(10 * time.Second)
	for {
		conn, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			break
		}
		require.True(t, time.Now().Before(deadline), "openssl s_server did not start")
		time.Sleep(100 * time.Millisecond)
	}
	return addr, serverCert
}

// handshake connects with identity and reports whether s_server answered
// with a page, which it only does after verifying the client certificate.
func handshake(t *testing.T, addr string, server *x509.Certificate, identity []tls.Certificate) bool {
	t.Helper()
	roots := x509.NewCertPool()
	roots.AddCert(server)
	conn, err := tls.Dial("tcp", addr, &tls.Config{RootCAs: roots, Certificates: identity, MinVersion: tls.VersionTLS12})
	if err != nil {
		return false
	}
	defer conn.Close() //nolint:errcheck
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write([]byte("GET / HTTP/1.0\r\n\r\n")); err != nil {
		return false
	}
	line, err := bufio.NewReader(conn).ReadString('\n')
	return err == nil && strings.HasPrefix(line, "HTTP/1.0 200")
}

func TestExportCertificate_DrivesARealMutualTLSHandshake(t *testing.T) {
	for _, keyType := range []string{"RSA", "ECDSA"} {
		t.Run(keyType, func(t *testing.T) {
			h := newVersioningHarness(t)
			ctx := context.Background()

			root, err := h.svc.CreateSelfSignedCertificate(ctx, CreateCertificateRequest{
				Name: "client-root", KeyID: h.keyID, ValidityDays: 30, UserID: h.userID, VaultID: h.vaultID, IsCA: true,
			})
			require.NoError(t, err)
			rootRow, err := h.certRepo.Read(ctx, root.CertID, h.scope())
			require.NoError(t, err)
			rootKeyPEM, err := common.DecryptSecret(rootRow.PrivateKey)
			require.NoError(t, err)

			// The service cannot issue an intermediate CA, so build one with the
			// crypto helper and store it as a CA-signed row under the root.
			interKeyPEM, err := crypto.GenerateRSAKeyPEM(2048)
			require.NoError(t, err)
			interCertPEM, err := crypto.CreateCASignedCertificatePEM(interKeyPEM, model.KeyTypeRSA, rootRow.Certificate, rootKeyPEM,
				model.KeyTypeRSA, crypto.CertificateTemplate{CommonName: "client-intermediate", ValidityDays: 30, IsCA: true})
			require.NoError(t, err)
			interEnc, err := common.EncryptSecret(interKeyPEM)
			require.NoError(t, err)
			ca := &model.Certificate{ID: uuid.New(), UserID: h.userID, VaultID: h.vaultID, KeyID: h.keyID, CACertID: &root.CertID,
				Name: "client-intermediate", Certificate: interCertPEM, PrivateKey: interEnc, CreatedAt: time.Now(), Enabled: true, Version: 1}
			require.NoError(t, h.certRepo.Create(ctx, ca))

			leafKeyID := uuid.New()
			var leafKeyPEM string
			if keyType == "RSA" {
				leafKeyPEM, err = crypto.GenerateRSAKeyPEM(2048)
			} else {
				leafKeyPEM, err = crypto.GenerateECDSAKeyPEM("P-256")
			}
			require.NoError(t, err)
			enc, err := common.EncryptSecret(leafKeyPEM)
			require.NoError(t, err)
			k := &model.Key{ID: leafKeyID, UserID: h.userID, VaultID: h.vaultID, Name: "client-key", Type: model.KeyTypeRSA,
				Value: enc, Enabled: true, CreatedAt: time.Now(), Bits: 2048, Exportable: true}
			if keyType != "RSA" {
				k.Type, k.Bits, k.Curve = model.KeyTypeECDSA, 0, "P-256"
			}
			require.NoError(t, h.keyRepo.Create(ctx, k))
			leaf, err := h.svc.CreateCASignedCertificate(ctx, CreateCertificateRequest{
				Name: "client", KeyID: leafKeyID, CACertID: &ca.ID, ValidityDays: 30, UserID: h.userID, VaultID: h.vaultID, Exportable: true,
			})
			require.NoError(t, err)

			addr, server := startOpenSSLServer(t, rootRow.Certificate)
			require.False(t, handshake(t, addr, server, nil), "control: no client certificate is refused")

			pemRes, err := h.svc.ExportCertificate(ctx, h.scope(), leaf.CertID, ExportCertificateRequest{Format: model.ExportFormatPEM})
			require.NoError(t, err)
			require.Equal(t, 2, strings.Count(pemRes.CertificatePEM, "BEGIN CERTIFICATE"), "chain is leaf plus intermediate, root excluded")
			pair, err := tls.X509KeyPair([]byte(pemRes.CertificatePEM), []byte(pemRes.PrivateKeyPEM))
			require.NoError(t, err)
			require.True(t, handshake(t, addr, server, []tls.Certificate{pair}), "PEM identity")

			// Controls: without the intermediate the server cannot build the chain.
			require.False(t, handshake(t, addr, server, []tls.Certificate{{Certificate: pair.Certificate[:1], PrivateKey: pair.PrivateKey}}), "leaf alone is refused")
			// A key that does not belong to the leaf cannot complete the handshake.
			wrong, err := rsa.GenerateKey(rand.Reader, 2048)
			require.NoError(t, err)
			require.False(t, handshake(t, addr, server, []tls.Certificate{{Certificate: pair.Certificate, PrivateKey: wrong}}), "wrong key is refused")

			p12Res, err := h.svc.ExportCertificate(ctx, h.scope(), leaf.CertID, ExportCertificateRequest{Format: model.ExportFormatPKCS12, Password: strPtr("pw")})
			require.NoError(t, err)
			priv, cert, cas, err := pkcs12.DecodeChain(p12Res.PKCS12, "pw")
			require.NoError(t, err)
			require.Len(t, cas, 1, "pkcs12 carries the intermediate only")
			chain := [][]byte{cert.Raw}
			for _, c := range cas {
				chain = append(chain, c.Raw)
			}
			require.True(t, handshake(t, addr, server, []tls.Certificate{{Certificate: chain, PrivateKey: priv, Leaf: cert}}), "PKCS12 identity")
		})
	}
}
