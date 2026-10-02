package common

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// ErrOutputExists is returned by WritePrivateFile when something already
// exists at the path and overwrite is false.
var ErrOutputExists = errors.New("output file already exists")

// privateFileTempPattern names the temporary file WritePrivateFile writes
// next to its target.
const privateFileTempPattern = ".rocketvault-export-*"

// WritePrivateFile writes data to path with mode 0600, so that path either
// ends up holding all of data or is left as it was. It writes a temporary
// file in the same directory, syncs it and moves it into place. Without
// overwrite, an existing path is never replaced and a symlink is never
// followed, even if the path appears after the caller checked. With
// overwrite, the path itself is replaced. Missing parent directories are
// created with mode 0700.
func WritePrivateFile(path string, data []byte, overwrite bool) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}
	tmp, err := os.CreateTemp(dir, privateFileTempPattern)
	if err != nil {
		return fmt.Errorf("failed to create temporary file: %w", err)
	}
	tmpName := tmp.Name()
	// The temporary name never survives. On failure it may be partial, and
	// after a successful link it is a second name for the output. After a
	// successful rename it no longer exists, so it is not removed again.
	renamed := false
	defer func() {
		if !renamed {
			_ = os.Remove(tmpName)
		}
	}()

	if err := writeAndSync(tmp, data); err != nil {
		return err
	}
	if overwrite {
		if err := os.Rename(tmpName, path); err != nil {
			return fmt.Errorf("failed to move the export file into place: %w", err)
		}
		renamed = true
		return nil
	}
	if err := os.Link(tmpName, path); err != nil {
		if errors.Is(err, fs.ErrExist) {
			return ErrOutputExists
		}
		return fmt.Errorf("failed to move the export file into place: %w", err)
	}
	return nil
}

// writeAndSync sets f to mode 0600, writes data, syncs and closes it.
func writeAndSync(f *os.File, data []byte) error {
	if err := f.Chmod(0o600); err != nil {
		_ = f.Close()
		return fmt.Errorf("failed to set the export file mode: %w", err)
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return fmt.Errorf("failed to write the export file: %w", err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return fmt.Errorf("failed to write the export file: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("failed to write the export file: %w", err)
	}
	return nil
}
