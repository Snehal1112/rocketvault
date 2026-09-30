package certificates

import (
	"rocketvault/cmd/vaultcli"
	certServices "rocketvault/internal/services/certificates"
	"rocketvault/model"
)

// certColumns is how a certificate is printed, everywhere. `get` and `list`
// each spelled out their own headers and cells before.
var certColumns = []vaultcli.Column[model.Certificate]{
	vaultcli.Col("ID", func(c model.Certificate) string { return vaultcli.CellUUID(c.ID) }),
	vaultcli.Col("Name", func(c model.Certificate) string { return c.Name }),
	vaultcli.Col("Version", func(c model.Certificate) string { return vaultcli.CellInt(c.CurrentVersion()) }),
	vaultcli.Col("Tags", func(c model.Certificate) string { return vaultcli.CellCSV(c.Tags) }),
	vaultcli.Col("Expires", func(c model.Certificate) string { return vaultcli.CellOptTime(c.ExpiresAt) }),
	vaultcli.Col("AutoRenew", func(c model.Certificate) string { return vaultcli.CellBool(c.AutoRenew) }),
	vaultcli.Col("Created", func(c model.Certificate) string { return vaultcli.CellTime(c.CreatedAt) }),
}

// createdCertColumns is what `create` prints. Deliberately narrower than
// certColumns: CreateCertificateResult carries no tags, expiry or auto-renew
// flag, and printing empty columns for them would suggest they were unset
// rather than simply not returned.
var createdCertColumns = []vaultcli.Column[*certServices.CreateCertificateResult]{
	vaultcli.Col("ID", func(r *certServices.CreateCertificateResult) string { return vaultcli.CellUUID(r.CertID) }),
	vaultcli.Col("Name", func(r *certServices.CreateCertificateResult) string { return r.Name }),
	vaultcli.Col("Created", func(r *certServices.CreateCertificateResult) string { return vaultcli.CellTime(r.CreatedAt) }),
}

// certPolicyColumns is what `rotation-policy get` prints.
var certPolicyColumns = []vaultcli.Column[*model.CertificatePolicy]{
	vaultcli.Col("Validity-Months", func(p *model.CertificatePolicy) string { return vaultcli.CellInt(p.ValidityMonths) }),
	vaultcli.Col("Key-Type", func(p *model.CertificatePolicy) string { return p.KeyType }),
	vaultcli.Col("Key-Size", func(p *model.CertificatePolicy) string { return vaultcli.CellInt(p.KeySize) }),
	vaultcli.Col("Curve", func(p *model.CertificatePolicy) string { return p.Curve }),
	vaultcli.Col("Subject", func(p *model.CertificatePolicy) string { return p.Subject }),
	vaultcli.Col("SANs", func(p *model.CertificatePolicy) string { return p.SANs }),
	vaultcli.Col("Auto-Renew", func(p *model.CertificatePolicy) string { return vaultcli.CellBool(p.AutoRenew) }),
	vaultcli.Col("Days-Before-Expiry", func(p *model.CertificatePolicy) string {
		return vaultcli.CellInt(p.DaysBeforeExpiry)
	}),
	vaultcli.Col("Issuer-Name", func(p *model.CertificatePolicy) string { return p.IssuerName }),
	vaultcli.Col("Updated", func(p *model.CertificatePolicy) string { return vaultcli.CellTime(p.UpdatedAt) }),
}

// certPolicyListColumns is what `rotation-policy list` prints. Its Auto-Renew
// and Days-Before-Expiry come from the policy record, not from the
// certificate row's own auto_renew/renewal_days -- the two can disagree, and
// only the certificate's own fields drive the renewal scheduler. See the list
// command's help text.
var certPolicyListColumns = []vaultcli.Column[model.CertificatePolicyWithCertName]{
	vaultcli.Col("Certificate-ID", func(p model.CertificatePolicyWithCertName) string {
		return vaultcli.CellUUID(p.CertificateID)
	}),
	vaultcli.Col("Certificate-Name", func(p model.CertificatePolicyWithCertName) string { return p.CertificateName }),
	vaultcli.Col("Validity-Months", func(p model.CertificatePolicyWithCertName) string {
		return vaultcli.CellInt(p.ValidityMonths)
	}),
	vaultcli.Col("Auto-Renew", func(p model.CertificatePolicyWithCertName) string { return vaultcli.CellBool(p.AutoRenew) }),
	vaultcli.Col("Days-Before-Expiry", func(p model.CertificatePolicyWithCertName) string {
		return vaultcli.CellInt(p.DaysBeforeExpiry)
	}),
}

// certVersionColumns is how a certificate version is printed. There is no
// column for a PEM or a key: model.CertificateVersion carries neither.
var certVersionColumns = []vaultcli.Column[model.CertificateVersion]{
	vaultcli.Col("Version", func(v model.CertificateVersion) string { return vaultcli.CellInt(v.Version) }),
	vaultcli.Col("Current", func(v model.CertificateVersion) string { return vaultcli.CellBool(v.Current) }),
	vaultcli.Col("Enabled", func(v model.CertificateVersion) string { return vaultcli.CellBool(v.Enabled) }),
	vaultcli.Col("Not-Before", func(v model.CertificateVersion) string { return vaultcli.CellOptTime(v.NotBefore) }),
	vaultcli.Col("Expires", func(v model.CertificateVersion) string { return vaultcli.CellOptTime(v.ExpiresAt) }),
	vaultcli.Col("Created", func(v model.CertificateVersion) string { return vaultcli.CellTime(v.CreatedAt) }),
}
