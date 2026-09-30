package certificates

import (
	"context"
	"fmt"

	"github.com/google/uuid"

	"rocketvault/internal/repositories"
	"rocketvault/model"
)

// fakeCertVersionRepo is an in-memory CertificateVersionRepositoryInterface.
// When certRepo is set, ArchiveAndRenew forwards the renewed row to
// certRepo.Update, so fixtures written before versioning, which capture the
// renewed certificate from an Update stub, keep working unchanged.
type fakeCertVersionRepo struct {
	certRepo *mockCertRepository

	archived []model.CertificateVersionRecord
	renewed  *model.Certificate
	stored   []model.CertificateVersion

	archiveErr error
	currentErr error

	currentUpdates  []model.CertificateVersionAttributes
	archivedUpdates map[int]model.CertificateVersionAttributes
}

func (f *fakeCertVersionRepo) ArchiveAndRenew(ctx context.Context, archived model.CertificateVersionRecord, renewed *model.Certificate, scope model.Scope) error {
	if f.archiveErr != nil {
		return f.archiveErr
	}
	f.archived = append(f.archived, archived)
	f.renewed = renewed
	if f.certRepo != nil {
		return f.certRepo.Update(ctx, renewed, scope)
	}
	return nil
}

func (f *fakeCertVersionRepo) CreateVersion(_ context.Context, rec *model.CertificateVersionRecord) error {
	f.archived = append(f.archived, *rec)
	return nil
}

func (f *fakeCertVersionRepo) ListVersions(_ context.Context, _ uuid.UUID) ([]model.CertificateVersion, error) {
	return append([]model.CertificateVersion(nil), f.stored...), nil
}

func (f *fakeCertVersionRepo) GetVersion(_ context.Context, certID uuid.UUID, version int) (*model.CertificateVersion, error) {
	for _, v := range f.stored {
		if v.Version == version {
			found := v
			return &found, nil
		}
	}
	return nil, fmt.Errorf("%w: certificate %s has no archived version %d", repositories.ErrCertificateVersionNotFound, certID, version)
}

func (f *fakeCertVersionRepo) ListVersionRecords(_ context.Context, _ uuid.UUID) ([]model.CertificateVersionRecord, error) {
	return f.archived, nil
}

func (f *fakeCertVersionRepo) UpdateVersionLifecycle(_ context.Context, certID uuid.UUID, version int, attrs model.CertificateVersionAttributes) error {
	for _, v := range f.stored {
		if v.Version == version {
			if f.archivedUpdates == nil {
				f.archivedUpdates = map[int]model.CertificateVersionAttributes{}
			}
			f.archivedUpdates[version] = attrs
			return nil
		}
	}
	return fmt.Errorf("%w: certificate %s has no archived version %d", repositories.ErrCertificateVersionNotFound, certID, version)
}

func (f *fakeCertVersionRepo) UpdateCurrentLifecycle(_ context.Context, _ uuid.UUID, _ int, attrs model.CertificateVersionAttributes, _ model.Scope) error {
	if f.currentErr != nil {
		return f.currentErr
	}
	f.currentUpdates = append(f.currentUpdates, attrs)
	return nil
}

// newCertSvcWithVersions builds the service with an explicit version fake.
func newCertSvcWithVersions(certRepo *mockCertRepository, keyRepo *mockKeyRepo, versions *fakeCertVersionRepo) CertificateService {
	return NewCertificateService(CertificateServiceConfig{
		CertificateRepository: certRepo,
		KeyRepository:         keyRepo,
		VersionRepository:     versions,
		Logger:                newTestCertLogger(),
	})
}
