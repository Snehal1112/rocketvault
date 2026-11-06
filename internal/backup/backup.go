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
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"rocketvault/common"
	"rocketvault/internal/db"
	"rocketvault/internal/logging"
)

// BackupMetadata contains metadata about a backup. Filename, Size and ModTime
// are always populated from the filesystem, regardless of whether the file's
// payload could be read. Readable is false when the file's contents could not
// be parsed as plaintext backup JSON -- either because it is encrypted (the
// expected case for a default "backup create") or genuinely corrupt. When
// Readable is false, Version, Timestamp, TableCount and RecordCount are their
// zero values and must not be treated as real data; Encrypted is set true in
// that case as a best-effort inference from content, not a decrypted fact.
type BackupMetadata struct {
	Filename    string    `json:"filename"`
	Size        int64     `json:"size"`
	ModTime     time.Time `json:"mod_time"`
	Readable    bool      `json:"readable"`
	Version     string    `json:"version,omitempty"`
	Timestamp   time.Time `json:"timestamp,omitempty"`
	Database    string    `json:"database,omitempty"`
	TableCount  int       `json:"table_count,omitempty"`
	RecordCount int       `json:"record_count,omitempty"`
	Encrypted   bool      `json:"encrypted"`
	Checksum    string    `json:"checksum,omitempty"`
}

// TableData represents data from a single table
type TableData struct {
	Name     string                   `json:"name"`
	Columns  []string                 `json:"columns"`
	Rows     []map[string]interface{} `json:"rows"`
	RowCount int                      `json:"row_count"`
}

// BackupData represents the complete backup structure
type BackupData struct {
	Metadata BackupMetadata `json:"metadata"`
	Tables   []TableData    `json:"tables"`
}

// Manager handles backup and restore operations
type Manager struct {
	db      *sql.DB
	dialect db.Dialect
	logger  *logging.Logger
}

// NewManager creates a new backup manager. The dialect drives engine-specific
// introspection queries (table and column listing).
func NewManager(sqlDB *sql.DB, dialect db.Dialect, logger *logging.Logger) *Manager {
	return &Manager{
		db:      sqlDB,
		dialect: dialect,
		logger:  logger,
	}
}

// CreateBackup creates a backup of the database
func (m *Manager) CreateBackup(outputPath string, encrypt bool) error {
	m.logger.Info("Starting database backup")

	// Read every table in one transaction so the export is one consistent
	// snapshot. Otherwise audit_chain_head and audit_logs can disagree.
	ctx := context.Background()
	tx, err := m.db.BeginTx(ctx, m.snapshotTxOptions())
	if err != nil {
		return fmt.Errorf("failed to begin backup read transaction: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck

	// Get all table names
	tables, err := m.getTableNames(ctx, tx)
	if err != nil {
		return fmt.Errorf("failed to get table names: %w", err)
	}

	backupData := BackupData{
		Metadata: BackupMetadata{
			Version:    "1.0",
			Timestamp:  time.Now(),
			TableCount: len(tables),
			Encrypted:  encrypt,
		},
		Tables: make([]TableData, 0, len(tables)),
	}

	totalRecords := 0

	// Export data from each table
	for _, tableName := range tables {
		tableData, err := m.exportTableData(ctx, tx, tableName)
		if err != nil {
			return fmt.Errorf("failed to export table %s: %w", tableName, err)
		}

		backupData.Tables = append(backupData.Tables, *tableData)
		totalRecords += tableData.RowCount
		m.logger.WithField("table", tableName).WithField("records", tableData.RowCount).Info("Exported table")
	}

	// End the read transaction before the slow file write.
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to end backup read transaction: %w", err)
	}

	backupData.Metadata.RecordCount = totalRecords

	// Create backup file
	if err := m.writeBackupFile(backupData, outputPath, encrypt); err != nil {
		return fmt.Errorf("failed to write backup file: %w", err)
	}

	m.logger.WithFields(map[string]interface{}{
		"file":      outputPath,
		"tables":    len(tables),
		"records":   totalRecords,
		"encrypted": encrypt,
	}).Info("Backup completed successfully")

	return nil
}

// RestoreBackup restores the database from a backup file
func (m *Manager) RestoreBackup(backupPath string, encrypted bool) error {
	m.logger.Info("Starting database restore")

	// Read and parse backup file
	backupData, err := m.readBackupFile(backupPath, encrypted)
	if err != nil {
		return fmt.Errorf("failed to read backup file: %w", err)
	}

	// Validate backup data
	if err := m.validateBackupData(backupData); err != nil {
		return fmt.Errorf("invalid backup data: %w", err)
	}

	// Determine restore order by FK dependency, not the backup file's own
	// (alphabetical) table order -- see table_order.go. Index the backup's
	// tables by name so both phases below can look them up regardless of
	// what order they appear in the file.
	byName := make(map[string]*TableData, len(backupData.Tables))
	names := make([]string, 0, len(backupData.Tables))
	for i := range backupData.Tables {
		byName[backupData.Tables[i].Name] = &backupData.Tables[i]
		names = append(names, backupData.Tables[i].Name)
	}
	order, err := topologicalOrder(names)
	if err != nil {
		return fmt.Errorf("determine table restore order: %w", err)
	}

	// Begin transaction for restore
	ctx := context.Background()
	tx, err := m.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck

	// Delete phase: children before parents (reverse topological order), so
	// clearing a table never violates an FK still pointing at a row in a
	// table cleared later.
	for i := len(order) - 1; i >= 0; i-- {
		if _, err := tx.Exec(fmt.Sprintf("DELETE FROM %s", order[i])); err != nil {
			return fmt.Errorf("failed to clear table %s: %w", order[i], err)
		}
	}

	// Insert phase: parents before children (topological order), so
	// inserting a row never violates an FK pointing at a not-yet-restored
	// parent row.
	totalRecords := 0
	for _, name := range order {
		tableData := byName[name]
		if err := m.insertTableData(tx, tableData); err != nil {
			return fmt.Errorf("failed to restore table %s: %w", name, err)
		}
		totalRecords += tableData.RowCount
		m.logger.WithField("table", tableData.Name).WithField("records", tableData.RowCount).Info("Restored table")
	}

	// The restored audit_logs may not match the restored or the live chain
	// head, so recompute the head from the rows in the same transaction.
	if err := m.resetAuditChainHead(ctx, tx); err != nil {
		return fmt.Errorf("failed to recompute audit chain head: %w", err)
	}

	// Commit transaction
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	m.logger.WithFields(map[string]interface{}{
		"file":    backupPath,
		"tables":  len(backupData.Tables),
		"records": totalRecords,
	}).Info("Restore completed successfully")

	return nil
}

// ListBackups lists available backup files in a directory. A backup that
// cannot be read as plaintext JSON -- e.g. a normal encrypted backup --
// still appears as a row via getBackupMetadata's content-based fallback;
// only a real filesystem error (permission denied, file removed mid-scan)
// causes a file to be skipped, and that skip is still logged as a warning.
func (m *Manager) ListBackups(backupDir string) ([]BackupMetadata, error) {
	files, err := filepath.Glob(filepath.Join(backupDir, "*.backup"))
	if err != nil {
		return nil, fmt.Errorf("failed to list backup files: %w", err)
	}

	var backups []BackupMetadata
	for _, file := range files {
		metadata, err := m.getBackupMetadata(file)
		if err != nil {
			m.logger.WithField("file", file).WithError(err).Warn("Failed to read backup metadata")
			continue
		}
		backups = append(backups, *metadata)
	}

	return backups, nil
}

// snapshotTxOptions returns the options for the backup read transaction.
// Postgres gets a read-only REPEATABLE READ snapshot. SQLite keeps the
// default, because one SQLite transaction already reads a single snapshot.
func (m *Manager) snapshotTxOptions() *sql.TxOptions {
	if m.dialect == db.Postgres {
		return &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true}
	}
	return nil
}

// resetAuditChainHead recomputes audit_chain_head from the restored
// audit_logs rows. It does nothing when the database has no chain tables.
func (m *Manager) resetAuditChainHead(ctx context.Context, tx *sql.Tx) error {
	tables, err := m.getTableNames(ctx, tx)
	if err != nil {
		return err
	}
	var hasLogs, hasHead bool
	for _, name := range tables {
		switch name {
		case "audit_logs":
			hasLogs = true
		case "audit_chain_head":
			hasHead = true
		}
	}
	if !hasLogs || !hasHead {
		return nil
	}
	return db.ResetAuditChainHead(ctx, tx, m.dialect)
}

// getTableNames retrieves all table names from the database
func (m *Manager) getTableNames(ctx context.Context, q db.DBTX) ([]string, error) {
	query := `
		SELECT name FROM sqlite_master
		WHERE type='table' AND name NOT LIKE 'sqlite_%'
		ORDER BY name
	`
	if m.dialect == db.Postgres {
		query = `
			SELECT table_name FROM information_schema.tables
			WHERE table_schema = 'public' AND table_type = 'BASE TABLE'
			ORDER BY table_name
		`
	}
	rows, err := q.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck

	var tables []string
	for rows.Next() {
		var tableName string
		if err := rows.Scan(&tableName); err != nil {
			return nil, err
		}
		tables = append(tables, tableName)
	}

	return tables, rows.Err()
}

// exportTableData exports all data from a specific table
func (m *Manager) exportTableData(ctx context.Context, q db.DBTX, tableName string) (*TableData, error) {
	// Get column information
	columns, err := m.getTableColumns(ctx, q, tableName)
	if err != nil {
		return nil, err
	}

	// Query all data from the table
	query := fmt.Sprintf("SELECT * FROM %s", tableName)
	rows, err := q.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck

	// Convert rows to map format
	var tableRows []map[string]interface{}
	for rows.Next() {
		values := make([]interface{}, len(columns))
		valuePtrs := make([]interface{}, len(columns))
		for i := range values {
			valuePtrs[i] = &values[i]
		}

		if err := rows.Scan(valuePtrs...); err != nil {
			return nil, err
		}

		row := make(map[string]interface{})
		for i, col := range columns {
			row[col] = values[i]
		}
		tableRows = append(tableRows, row)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return &TableData{
		Name:     tableName,
		Columns:  columns,
		Rows:     tableRows,
		RowCount: len(tableRows),
	}, nil
}

// getTableColumns gets column names for a table
func (m *Manager) getTableColumns(ctx context.Context, q db.DBTX, tableName string) ([]string, error) {
	if m.dialect == db.Postgres {
		return m.getTableColumnsPostgres(ctx, q, tableName)
	}

	query := fmt.Sprintf("PRAGMA table_info(%s)", tableName)
	rows, err := q.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck

	var columns []string
	for rows.Next() {
		var cid int
		var name, ctype string
		var notnull, pk int
		var dfltValue interface{}

		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dfltValue, &pk); err != nil {
			return nil, err
		}
		columns = append(columns, name)
	}

	return columns, rows.Err()
}

// getTableColumnsPostgres lists columns via information_schema for PostgreSQL.
func (m *Manager) getTableColumnsPostgres(ctx context.Context, q db.DBTX, tableName string) ([]string, error) {
	rows, err := q.QueryContext(ctx,
		`SELECT column_name FROM information_schema.columns
		 WHERE table_schema = 'public' AND table_name = $1
		 ORDER BY ordinal_position`,
		tableName,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck

	var columns []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		columns = append(columns, name)
	}

	return columns, rows.Err()
}

// writeBackupFile writes the backup data to a file
func (m *Manager) writeBackupFile(data BackupData, outputPath string, encrypt bool) error {
	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return err
	}

	var finalData []byte
	if encrypt {
		encrypted, err := common.EncryptSecret(string(jsonData))
		if err != nil {
			return fmt.Errorf("failed to encrypt backup: %w", err)
		}
		finalData = []byte(encrypted)
	} else {
		finalData = jsonData
	}

	// Ensure directory exists
	dir := filepath.Dir(outputPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create backup directory: %w", err)
	}

	// Write to file
	if err := os.WriteFile(outputPath, finalData, 0600); err != nil {
		return fmt.Errorf("failed to write backup file: %w", err)
	}

	return nil
}

// readBackupFile reads and parses a backup file
func (m *Manager) readBackupFile(backupPath string, encrypted bool) (*BackupData, error) {
	data, err := os.ReadFile(backupPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read backup file: %w", err)
	}

	var jsonData string
	if encrypted {
		jsonData, err = common.DecryptSecret(string(data))
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt backup: %w", err)
		}
	} else {
		jsonData = string(data)
	}

	var backupData BackupData
	if err := json.Unmarshal([]byte(jsonData), &backupData); err != nil {
		return nil, fmt.Errorf("failed to parse backup data: %w", err)
	}

	return &backupData, nil
}

// validateBackupData validates the backup data structure
func (m *Manager) validateBackupData(data *BackupData) error {
	if data.Metadata.Version == "" {
		return fmt.Errorf("missing backup version")
	}
	if data.Metadata.TableCount != len(data.Tables) {
		return fmt.Errorf("table count mismatch: expected %d, got %d", data.Metadata.TableCount, len(data.Tables))
	}
	return nil
}

// insertTableData inserts all rows for a specific table. The caller (RestoreBackup)
// is responsible for clearing the table first, in the correct FK-safe order --
// this function only inserts.
func (m *Manager) insertTableData(tx *sql.Tx, tableData *TableData) error {
	if len(tableData.Rows) == 0 {
		return nil
	}

	columnsStr := ""
	for i, col := range tableData.Columns {
		if i > 0 {
			columnsStr += ", "
		}
		columnsStr += col
	}

	placeholdersStr := ""
	for i := range tableData.Columns {
		if i > 0 {
			placeholdersStr += ", "
		}
		placeholdersStr += "?"
	}

	query := fmt.Sprintf("INSERT INTO %s (%s) VALUES (%s)",
		tableData.Name, columnsStr, placeholdersStr)

	// Rebind "?" placeholders for the active engine before preparing.
	query = m.dialect.Rebind(query)

	stmt, err := tx.Prepare(query)
	if err != nil {
		return err
	}
	defer stmt.Close() //nolint:errcheck

	args := make([]interface{}, len(tableData.Columns))
	for _, row := range tableData.Rows {
		for i, col := range tableData.Columns {
			args[i] = row[col]
		}
		if _, err := stmt.Exec(args...); err != nil {
			return err
		}
	}

	return nil
}

// getBackupMetadata reads metadata from a backup file. It never requires or
// touches the master key: detection is content-based (does the file parse as
// plaintext backup JSON?), never decryption-based. A file that fails that
// parse -- encrypted or corrupt -- still returns filesystem-derived metadata
// with Readable set to false, rather than an error; only a real filesystem
// failure (the file can't be opened, stat'd or read) returns an error.
func (m *Manager) getBackupMetadata(backupPath string) (*BackupMetadata, error) {
	f, err := os.Open(backupPath)
	if err != nil {
		return nil, err
	}
	defer f.Close() //nolint:errcheck

	info, err := f.Stat()
	if err != nil {
		return nil, err
	}

	data, err := io.ReadAll(f)
	if err != nil {
		return nil, err
	}

	base := BackupMetadata{
		Filename: filepath.Base(backupPath),
		Size:     info.Size(),
		ModTime:  info.ModTime(),
	}

	content := string(data)

	// A file whose contents don't start with '{' isn't plaintext backup
	// JSON -- it's either an encrypted backup (the default "backup create"
	// output) or genuinely corrupt. Either way, list it: the filesystem
	// fields above are still real, even though the payload isn't readable
	// without the master key, which this function never touches.
	if len(content) == 0 || content[0] != '{' {
		base.Encrypted = true
		return &base, nil
	}

	var backupData BackupData
	if err := json.Unmarshal([]byte(content), &backupData); err != nil {
		// Starts with '{' but isn't valid backup JSON: also genuinely
		// corrupt. Same treatment -- list what the filesystem knows, no
		// payload fields.
		base.Encrypted = true
		return &base, nil
	}

	// Valid JSON that unmarshals cleanly can still be unrelated to a backup
	// -- e.g. "{}" or "{"hello":"world"}" -- which would otherwise produce an
	// all-zero BackupData and be reported as a genuine, readable backup. An
	// empty Version is the same minimum-viability check validateBackupData
	// uses to reject a restore, so apply it here too: treat it as unreadable
	// rather than fabricating a fake-but-plausible metadata row.
	if backupData.Metadata.Version == "" {
		base.Encrypted = true
		return &base, nil
	}

	md := backupData.Metadata
	md.Filename = base.Filename
	md.Size = base.Size
	md.ModTime = base.ModTime
	md.Readable = true
	return &md, nil
}
