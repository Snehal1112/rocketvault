package validation

import (
	validation "github.com/go-ozzo/ozzo-validation/v4"

	"rocketvault/model"
)

// CertificateCreateRequest is the input for creating a certificate.
type CertificateCreateRequest struct {
	Name         string
	Tags         []string
	ValidityDays int
}

// ValidateCertificateCreate validates certificate creation input. A
// non-positive ValidityDays is rejected by the caller before this runs;
// validation.Max skips the zero value, so it only enforces the cap (B78).
func ValidateCertificateCreate(req CertificateCreateRequest) error {
	return validation.ValidateStruct(&req,
		validation.Field(&req.Name,
			validation.Required,
			validation.Length(1, 127),
			CertificateNameRule(),
		),
		validation.Field(&req.Tags,
			validation.Length(0, 15),
			validation.Each(validation.Length(1, 256)),
		),
		validation.Field(&req.ValidityDays,
			validation.Max(model.MaxCertificateValidityDays),
		),
	)
}

// CertificateNameRule validates certificate names.
func CertificateNameRule() validation.Rule {
	return validation.Match(CertificateNamePattern).Error("must contain only alphanumeric characters and hyphens, and start with a letter")
}
