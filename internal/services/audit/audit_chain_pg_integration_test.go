//go:build integration

package audit_test

import (
	"context"
	"database/sql"
	"testing"
	"time"

	_ "github.com/lib/pq"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	rvdb "rocketvault/internal/db"
	"rocketvault/internal/logging"
	"rocketvault/internal/repositories"
	auditSvc "rocketvault/internal/services/audit"
)

// TestAuditChain_TwoServicesOneDB_Postgres simulates two replicas on one Postgres.
func TestAuditChain_TwoServicesOneDB_Postgres(t *testing.T) {
	ctx := context.Background()
	container, err := tcpostgres.Run(ctx,
		"postgres:16-alpine",
		tcpostgres.WithDatabase("rocketvault"),
		tcpostgres.WithUsername("rv"),
		tcpostgres.WithPassword("rv-secret"),
		tcpostgres.BasicWaitStrategies(),
		tcpostgres.WithSQLDriver("postgres"),
		testcontainers.WithAdditionalWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(60*time.Second),
		),
	)
	require.NoError(t, err, "start postgres container")
	t.Cleanup(func() { _ = container.Terminate(ctx) })

	dsn, err := container.ConnectionString(ctx, "sslmode=disable")
	require.NoError(t, err)

	open := func() *sql.DB {
		db, err := sql.Open("postgres", dsn)
		require.NoError(t, err)
		db.SetMaxOpenConns(10)
		t.Cleanup(func() { db.Close() }) //nolint:errcheck,gosec
		require.Eventually(t, func() bool { return db.PingContext(ctx) == nil },
			60*time.Second, 500*time.Millisecond, "postgres did not become ready")
		return db
	}
	dbA, dbB := open(), open()
	require.NoError(t, rvdb.NewRepository(logging.InitLogger()).SetupSchema(dbA, rvdb.Postgres))

	repoA := repositories.NewAuditRepository(rvdb.NewConn(dbA, rvdb.Postgres))
	repoB := repositories.NewAuditRepository(rvdb.NewConn(dbB, rvdb.Postgres))
	svcs := []auditSvc.AuditServiceInterface{auditSvc.NewAuditService(repoA), auditSvc.NewAuditService(repoB)}

	for _, err := range runWriters(svcs, 10) {
		require.NoError(t, err)
	}
	assertChainIntact(t, repoA, 20)
	assertChainIntact(t, repoB, 20)
}
