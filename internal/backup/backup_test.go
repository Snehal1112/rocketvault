/*
Copyright © 2025 Snehal Dangroshiya

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/

package backup

import (
	"database/sql"
	"os"
	"path/filepath"
	"testing"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/spf13/viper"

	rvdb "rocketvault/internal/db"
	"rocketvault/internal/logging"
)

func TestMain(m *testing.M) {
	// Set master_key once before any test runs so parallel tests don't race on
	// the global viper map. All backup tests use the same test key.
	// A fresh, unrelated 32-byte key — not the compromised value that used to
	// ship in .rocketvault.yaml (rotated 2026-08-16, see docs/known-bugs.md
	// § B10). This test only needs *a* valid master key, never a specific one.
	os.Setenv("MASTER_KEY", "i7I2y3WZofTpqkICx3HuWe8BJldU6TFDQk4HIlUF0K4=") //nolint:errcheck,gosec
	viper.AutomaticEnv()
	os.Exit(m.Run())
}

func setupTestDB(t *testing.T) (*sql.DB, func()) {
	// Create temporary database
	tmpDir, err := os.MkdirTemp("", "backup_test_*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}

	dbPath := filepath.Join(tmpDir, "test.db")
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		t.Fatalf("Failed to open database: %v", err)
	}

	// Create test tables
	_, err = db.Exec(`
		CREATE TABLE users (
			id TEXT PRIMARY KEY,
			username TEXT UNIQUE NOT NULL,
			password_hash TEXT NOT NULL,
			role TEXT NOT NULL
		);
		CREATE TABLE secrets (
			id TEXT PRIMARY KEY,
			user_id TEXT NOT NULL,
			name TEXT NOT NULL,
			value TEXT NOT NULL,
			version INTEGER NOT NULL,
			FOREIGN KEY (user_id) REFERENCES users(id)
		);
	`)
	if err != nil {
		t.Fatalf("Failed to create tables: %v", err)
	}

	// Insert test data
	_, err = db.Exec(`
		INSERT INTO users (id, username, password_hash, role) VALUES
		('user1', 'testuser', 'hash1', 'user'),
		('user2', 'admin', 'hash2', 'admin');
		INSERT INTO secrets (id, user_id, name, value, version) VALUES
		('secret1', 'user1', 'db-password', 'secret123', 1),
		('secret2', 'user1', 'api-key', 'key456', 1);
	`)
	if err != nil {
		t.Fatalf("Failed to insert test data: %v", err)
	}

	cleanup := func() {
		db.Close()           //nolint:errcheck,gosec
		os.RemoveAll(tmpDir) //nolint:errcheck,gosec
	}

	return db, cleanup
}

func TestBackupManager(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	logger := logging.InitLogger()
	manager := NewManager(db, rvdb.SQLite, logger)

	t.Run("CreateBackup", func(t *testing.T) {
		tmpDir, err := os.MkdirTemp("", "backup_test_*")
		if err != nil {
			t.Fatalf("Failed to create temp dir: %v", err)
		}
		defer os.RemoveAll(tmpDir) //nolint:errcheck

		backupPath := filepath.Join(tmpDir, "test.backup")

		err = manager.CreateBackup(backupPath, false)
		if err != nil {
			t.Fatalf("CreateBackup failed: %v", err)
		}

		// Verify backup file exists
		if _, err := os.Stat(backupPath); os.IsNotExist(err) {
			t.Fatal("Backup file was not created")
		}
	})

	t.Run("CreateEncryptedBackup", func(t *testing.T) {
		tmpDir, err := os.MkdirTemp("", "backup_test_*")
		if err != nil {
			t.Fatalf("Failed to create temp dir: %v", err)
		}
		defer os.RemoveAll(tmpDir) //nolint:errcheck

		backupPath := filepath.Join(tmpDir, "encrypted.backup")

		err = manager.CreateBackup(backupPath, true)
		if err != nil {
			t.Fatalf("CreateEncryptedBackup failed: %v", err)
		}

		// Verify backup file exists
		if _, err := os.Stat(backupPath); os.IsNotExist(err) {
			t.Fatal("Encrypted backup file was not created")
		}
	})

	t.Run("BackupAndRestore", func(t *testing.T) {
		tmpDir, err := os.MkdirTemp("", "backup_test_*")
		if err != nil {
			t.Fatalf("Failed to create temp dir: %v", err)
		}
		defer os.RemoveAll(tmpDir) //nolint:errcheck

		backupPath := filepath.Join(tmpDir, "roundtrip.backup")

		// Create backup
		err = manager.CreateBackup(backupPath, false)
		if err != nil {
			t.Fatalf("CreateBackup failed: %v", err)
		}

		// Clear existing data
		_, err = db.Exec("DELETE FROM secrets; DELETE FROM users;")
		if err != nil {
			t.Fatalf("Failed to clear data: %v", err)
		}

		// Restore from backup
		err = manager.RestoreBackup(backupPath, false)
		if err != nil {
			t.Fatalf("RestoreBackup failed: %v", err)
		}

		// Verify data was restored
		var userCount, secretCount int
		err = db.QueryRow("SELECT COUNT(*) FROM users").Scan(&userCount)
		if err != nil {
			t.Fatalf("Failed to count users: %v", err)
		}
		err = db.QueryRow("SELECT COUNT(*) FROM secrets").Scan(&secretCount)
		if err != nil {
			t.Fatalf("Failed to count secrets: %v", err)
		}

		if userCount != 2 {
			t.Errorf("Expected 2 users, got %d", userCount)
		}
		if secretCount != 2 {
			t.Errorf("Expected 2 secrets, got %d", secretCount)
		}
	})

	t.Run("ListBackups", func(t *testing.T) {
		tmpDir, err := os.MkdirTemp("", "backup_test_*")
		if err != nil {
			t.Fatalf("Failed to create temp dir: %v", err)
		}
		defer os.RemoveAll(tmpDir) //nolint:errcheck

		// Create some backup files
		backup1 := filepath.Join(tmpDir, "backup1.backup")
		backup2 := filepath.Join(tmpDir, "backup2.backup")

		err = manager.CreateBackup(backup1, false)
		if err != nil {
			t.Fatalf("Failed to create backup1: %v", err)
		}

		// Wait a moment to ensure different timestamps
		time.Sleep(100 * time.Millisecond)

		err = manager.CreateBackup(backup2, false)
		if err != nil {
			t.Fatalf("Failed to create backup2: %v", err)
		}

		// List backups
		backups, err := manager.ListBackups(tmpDir)
		if err != nil {
			t.Fatalf("ListBackups failed: %v", err)
		}

		if len(backups) != 2 {
			t.Errorf("Expected 2 backups, got %d", len(backups))
		}

		// Verify metadata
		for _, backup := range backups {
			if backup.Version != "1.0" {
				t.Errorf("Expected version 1.0, got %s", backup.Version)
			}
			if backup.TableCount == 0 {
				t.Error("Expected non-zero table count")
			}
		}
	})
}

// TestRestoreBackup_PreservesReferentialIntegrity proves RestoreBackup's
// two-phase (delete-then-insert, each FK-ordered) restructure still
// round-trips correctly on this package's existing minimal SQLite fixture:
// every secret's user_id must still resolve to a real users row after
// restore, not just match row counts. SQLite's foreign_keys pragma is off
// by default (setupTestDB doesn't enable it), so this test cannot by itself
// prove the OLD alphabetical order would have failed -- it proves the NEW
// FK-ordered code path preserves existing correct behavior. The Postgres
// integration test (Task 4) is what proves the ordering itself matters,
// against an engine that actually enforces FK constraints.
func TestRestoreBackup_PreservesReferentialIntegrity(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	logger := logging.InitLogger()
	manager := NewManager(db, rvdb.SQLite, logger)

	tmpDir, err := os.MkdirTemp("", "backup_test_*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir) //nolint:errcheck
	backupPath := filepath.Join(tmpDir, "integrity.backup")

	if err := manager.CreateBackup(backupPath, false); err != nil {
		t.Fatalf("CreateBackup failed: %v", err)
	}

	// Mutate before restoring, so the restore's effect is observable.
	if _, err := db.Exec("DELETE FROM secrets; DELETE FROM users;"); err != nil {
		t.Fatalf("Failed to clear data: %v", err)
	}

	if err := manager.RestoreBackup(backupPath, false); err != nil {
		t.Fatalf("RestoreBackup failed: %v", err)
	}

	// setupTestDB seeds secret1/secret2, both owned by user1. Prove the
	// restored secrets still resolve to a real user row via an actual JOIN,
	// not just independently-matching counts on each table.
	var joinedCount int
	err = db.QueryRow(`
		SELECT COUNT(*) FROM secrets s
		JOIN users u ON u.id = s.user_id
	`).Scan(&joinedCount)
	if err != nil {
		t.Fatalf("Failed to count joined rows: %v", err)
	}
	if joinedCount != 2 {
		t.Errorf("expected 2 secrets with a resolvable user_id after restore, got %d", joinedCount)
	}
}

func TestBackupMetadata(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	logger := logging.InitLogger()
	manager := NewManager(db, rvdb.SQLite, logger)

	tmpDir, err := os.MkdirTemp("", "backup_test_*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir) //nolint:errcheck

	backupPath := filepath.Join(tmpDir, "metadata.backup")

	// Create backup
	err = manager.CreateBackup(backupPath, false)
	if err != nil {
		t.Fatalf("CreateBackup failed: %v", err)
	}

	// Get metadata
	metadata, err := manager.getBackupMetadata(backupPath)
	if err != nil {
		t.Fatalf("getBackupMetadata failed: %v", err)
	}

	// Verify metadata
	if metadata.Version != "1.0" {
		t.Errorf("Expected version 1.0, got %s", metadata.Version)
	}
	if metadata.TableCount == 0 {
		t.Error("Expected non-zero table count")
	}
	if metadata.RecordCount != 4 { // 2 users + 2 secrets
		t.Errorf("Expected 4 records, got %d", metadata.RecordCount)
	}
	if metadata.Encrypted {
		t.Error("Expected backup to be unencrypted")
	}
}
