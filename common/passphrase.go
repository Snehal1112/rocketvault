package common

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"strings"

	"golang.org/x/term"
)

// ErrNoPassphraseAvailable is returned when no passphrase source is configured
// and there is no terminal to prompt on. Callers must treat this as fatal and
// must never fall back to writing plaintext.
var ErrNoPassphraseAvailable = errors.New("no passphrase available and stdin is not a terminal")

// PassphraseSource describes where a passphrase may be read from.
type PassphraseSource struct {
	File    string
	EnvVar  string
	Prompt  string
	Confirm bool
	// ConfirmPrompt is the second prompt when Confirm is set. Empty means
	// "Confirm passphrase: ".
	ConfirmPrompt string
}

// ResolvePassphrase returns a passphrase from the first available source: an
// explicit file, then an environment variable, then an interactive prompt.
func ResolvePassphrase(src PassphraseSource) (string, error) {
	if src.File != "" {
		return passphraseFromFile(src.File)
	}
	if src.EnvVar != "" {
		if v := os.Getenv(src.EnvVar); v != "" {
			return v, nil
		}
	}
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return "", ErrNoPassphraseAvailable
	}
	return promptPassphrase(src)
}

func passphraseFromFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("failed to read passphrase file: %w", err)
	}
	defer f.Close() //nolint:errcheck

	scanner := bufio.NewScanner(f)
	if !scanner.Scan() {
		if err := scanner.Err(); err != nil {
			return "", fmt.Errorf("failed to read passphrase file: %w", err)
		}
		return "", fmt.Errorf("passphrase file %s is empty", path)
	}
	pass := strings.TrimSpace(scanner.Text())
	if pass == "" {
		return "", fmt.Errorf("passphrase file %s is empty", path)
	}
	return pass, nil
}

func promptPassphrase(src PassphraseSource) (string, error) {
	prompt := src.Prompt
	if prompt == "" {
		prompt = "Passphrase: "
	}

	fmt.Fprint(os.Stderr, prompt) //nolint:errcheck
	first, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr) //nolint:errcheck
	if err != nil {
		return "", fmt.Errorf("failed to read passphrase: %w", err)
	}
	if len(first) == 0 {
		return "", errors.New("passphrase must not be empty")
	}

	if src.Confirm {
		confirmPrompt := src.ConfirmPrompt
		if confirmPrompt == "" {
			confirmPrompt = "Confirm passphrase: "
		}
		fmt.Fprint(os.Stderr, confirmPrompt) //nolint:errcheck
		second, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr) //nolint:errcheck
		if err != nil {
			return "", fmt.Errorf("failed to read passphrase confirmation: %w", err)
		}
		if string(first) != string(second) {
			return "", errors.New("passphrases do not match")
		}
	}

	return string(first), nil
}
