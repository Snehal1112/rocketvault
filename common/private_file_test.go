package common

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// assertNoTempFiles fails if WritePrivateFile left a temporary file in dir.
func assertNoTempFiles(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	for _, e := range entries {
		assert.False(t, strings.HasPrefix(e.Name(), ".rocketvault-export-"), "temporary file left behind: %s", e.Name())
	}
}

func TestWritePrivateFile_CreatesFileAndDirectoriesPrivately(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "out.pem")
	require.NoError(t, WritePrivateFile(path, []byte("data"), false))

	got, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, "data", string(got))
	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
	dirInfo, err := os.Stat(filepath.Dir(path))
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o700), dirInfo.Mode().Perm())
	assertNoTempFiles(t, filepath.Dir(path))
}

func TestWritePrivateFile_NeverReplacesWithoutOverwrite(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out.pem")
	require.NoError(t, os.WriteFile(path, []byte("original"), 0o644))

	assert.ErrorIs(t, WritePrivateFile(path, []byte("new"), false), ErrOutputExists)
	got, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, "original", string(got))
	assertNoTempFiles(t, dir)
}

func TestWritePrivateFile_OverwriteReplacesAndTightensTheMode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out.pem")
	require.NoError(t, os.WriteFile(path, []byte("original"), 0o644))

	require.NoError(t, WritePrivateFile(path, []byte("new"), true))
	got, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, "new", string(got))
	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
	assertNoTempFiles(t, dir)
}

func TestWritePrivateFile_NeverFollowsASymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	require.NoError(t, os.WriteFile(target, []byte("keep"), 0o600))
	link := filepath.Join(dir, "link.pem")
	require.NoError(t, os.Symlink(target, link))

	assert.ErrorIs(t, WritePrivateFile(link, []byte("new"), false), ErrOutputExists)
	got, err := os.ReadFile(target)
	require.NoError(t, err)
	assert.Equal(t, "keep", string(got))
}

func TestWritePrivateFile_FailureLeavesNothingBehind(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
	locked := filepath.Join(t.TempDir(), "locked")
	require.NoError(t, os.Mkdir(locked, 0o500))
	t.Cleanup(func() { _ = os.Chmod(locked, 0o700) })

	require.Error(t, WritePrivateFile(filepath.Join(locked, "out.pem"), []byte("data"), false))
	entries, err := os.ReadDir(locked)
	require.NoError(t, err)
	assert.Empty(t, entries)
}

func TestWritePrivateFile_NeverFollowsADanglingSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "missing-target")
	link := filepath.Join(dir, "link.pem")
	require.NoError(t, os.Symlink(target, link))

	assert.ErrorIs(t, WritePrivateFile(link, []byte("new"), false), ErrOutputExists)
	_, err := os.Lstat(target)
	assert.ErrorIs(t, err, os.ErrNotExist)
	assertNoTempFiles(t, dir)
}

func TestWritePrivateFile_OverwriteReplacesTheSymlinkNotItsTarget(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	require.NoError(t, os.WriteFile(target, []byte("keep"), 0o644))
	link := filepath.Join(dir, "link.pem")
	require.NoError(t, os.Symlink(target, link))

	require.NoError(t, WritePrivateFile(link, []byte("new"), true))
	got, err := os.ReadFile(target)
	require.NoError(t, err)
	assert.Equal(t, "keep", string(got))
	info, err := os.Lstat(link)
	require.NoError(t, err)
	assert.True(t, info.Mode().IsRegular())
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
	assertNoTempFiles(t, dir)
}

func TestWritePrivateFile_DirectoryTargetLeavesNothingBehind(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out.pem")
	require.NoError(t, os.Mkdir(path, 0o700))

	assert.ErrorIs(t, WritePrivateFile(path, []byte("data"), false), ErrOutputExists)
	require.Error(t, WritePrivateFile(path, []byte("data"), true))
	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.True(t, info.IsDir())
	assertNoTempFiles(t, dir)
}

func TestWritePrivateFile_ErrorsCarryNoContent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out.pem")
	require.NoError(t, os.Mkdir(path, 0o700))

	err := WritePrivateFile(path, []byte("SECRET-KEY-MATERIAL"), true)
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "SECRET-KEY-MATERIAL")
}
