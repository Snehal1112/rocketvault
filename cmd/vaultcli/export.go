package vaultcli

import (
	"errors"
	"fmt"
	"os"

	"github.com/google/uuid"
	"github.com/spf13/cobra"

	"rocketvault/common"
	"rocketvault/internal/services/exportaudit"
)

// outputExistsMessage is the fixed message for an output file that already
// exists when --force was not given.
const outputExistsMessage = "the output file already exists: pass --force to replace it"

// ExportAttempt is one CLI certificate or key export attempt. It records
// exactly one structured audit event through exportaudit, whatever the
// outcome: the same event the HTTP export handlers write, with Source "cli".
// The CLI has no PolicyMiddleware, so this event is also the audit record of
// a denied attempt.
type ExportAttempt struct {
	s        *Session
	attempt  exportaudit.Attempt
	recorded bool
}

// BeginExportAttempt starts an attempt to export resourceType ("certificate"
// or "key"). rawID is the command's argument; it reaches the audit trail
// only when it parses as a UUID. format reaches it only when it is a known
// export format, so arbitrary command-line text is never audited.
func BeginExportAttempt(s *Session, resourceType, rawID, format string, version int) *ExportAttempt {
	id := ""
	if parsed, err := uuid.Parse(rawID); err == nil {
		id = parsed.String()
	}
	return &ExportAttempt{s: s, attempt: exportaudit.Attempt{
		UserID: s.Claims.UserID.String(), ResourceType: resourceType, ResourceID: id,
		Version: version, Format: exportaudit.AuditableFormat(format), Outcome: "failure", Source: "cli",
	}}
}

// Fail records f and returns an error carrying only f's fixed message. An
// internal failure shows a generic message instead, as the API does.
func (e *ExportAttempt) Fail(f exportaudit.Failure) error {
	e.note(f)
	msg := f.Message
	if f.Kind == exportaudit.KindInternal {
		msg = "internal error; see the RocketVault log for details"
	}
	return fmt.Errorf("failed to export %s: %s", e.attempt.ResourceType, msg)
}

// FailService classifies a service error, records it and returns the fixed
// message. The service's own error text is never shown, because it can name
// repository detail; an internal failure's cause goes to the log file only.
func (e *ExportAttempt) FailService(err error) error {
	f := exportaudit.Classify(err, e.attempt.ResourceType)
	if f.Kind == exportaudit.KindInternal && e.s.Log != nil {
		e.s.Log.WithField("operation", "export_"+e.attempt.ResourceType).
			WithField("step", f.Reason).WithError(err).Error("export failed")
	}
	return e.Fail(f)
}

// FailInput records a local input problem under the fixed reason and returns
// shown. shown must be an error this command built, and it never holds a
// passphrase or password.
func (e *ExportAttempt) FailInput(reason string, shown error) error {
	e.note(exportaudit.BadRequest(reason))
	return fmt.Errorf("failed to export %s: %w", e.attempt.ResourceType, shown)
}

// FailOutput records that the output file could not be written. The service
// already released the material, but no file holds it, so the attempt is a
// failure.
func (e *ExportAttempt) FailOutput(err error) error {
	if errors.Is(err, common.ErrOutputExists) {
		return e.Fail(exportaudit.BadRequest(outputExistsMessage))
	}
	if errors.Is(err, common.ErrHardLinksUnsupported) {
		// The sentinel's text is a fixed phrase, so it is safe to show.
		e.note(exportaudit.Failure{Kind: exportaudit.KindInternal, Code: "output_failed",
			Reason: "the output filesystem does not support hard links"})
		return fmt.Errorf("failed to export %s: %s", e.attempt.ResourceType, common.ErrHardLinksUnsupported.Error())
	}
	e.note(exportaudit.Failure{Kind: exportaudit.KindInternal, Code: "output_failed", Reason: "the output file could not be written"})
	return fmt.Errorf("failed to export %s: %w", e.attempt.ResourceType, err)
}

// Denied records an authorization failure and returns err, which
// Session.Authorize already shaped and logged. Authorize does not keep the
// vault it was refused in, so Denied resolves it again for the event.
func (e *ExportAttempt) Denied(err error) error {
	if sc, cerr := CtxContainer.From(e.s.Ctx); cerr == nil && sc != nil {
		if vaultID, verr := ResolveVaultID(e.s.Ctx, e.s.Cmd, sc); verr == nil {
			e.attempt.VaultID = vaultID.String()
		}
	}
	e.note(exportaudit.Forbidden("vault authorization failed"))
	return err
}

// Succeed records the successful export of name at version.
func (e *ExportAttempt) Succeed(name string, version int) {
	e.attempt.Outcome, e.attempt.Name, e.attempt.Version = "success", name, version
	e.attempt.Code, e.attempt.Reason = "", ""
	e.record()
}

// note records the failure f.
func (e *ExportAttempt) note(f exportaudit.Failure) {
	e.attempt.Code, e.attempt.Reason = f.Code, f.Reason
	if f.Name != "" {
		e.attempt.Name = f.Name
	}
	e.record()
}

// record writes the attempt's one audit event. Later calls do nothing, so an
// attempt is never audited twice. A failure before the vault is resolved
// records an empty vault id.
func (e *ExportAttempt) record() {
	if e.recorded {
		return
	}
	e.recorded = true
	if e.s.VaultID != uuid.Nil {
		e.attempt.VaultID = e.s.VaultID.String()
	}
	sc := e.s.Container
	if sc == nil {
		var err error
		if sc, err = CtxContainer.From(e.s.Ctx); err != nil || sc == nil {
			return
		}
	}
	exportaudit.Record(e.s.Ctx, sc.GetAuditService(), e.attempt)
}

// ExportOutput holds the output flags both item export commands share. The
// names, shorthands and defaults mirror "secrets export", plus --force.
type ExportOutput struct {
	File           string
	Encrypt        bool
	PassphraseFile string
	Force          bool
}

// AddExportOutputFlags registers --file/-o, --encrypt/-e, --passphrase-file
// and --force on cmd. --file is required.
func AddExportOutputFlags(cmd *cobra.Command) {
	cmd.Flags().StringP("file", "o", "", "Output file path (required)")
	cmd.Flags().BoolP("encrypt", "e", true, "Seal the file under a passphrase (argon2id + AES-256-GCM)")
	cmd.Flags().String("passphrase-file", "", "Read the export passphrase from the first line of this file")
	cmd.Flags().Bool("force", false, "Replace the output file if it already exists")
	cmd.MarkFlagRequired("file") //nolint:errcheck,gosec
}

// ReadExportOutput reads the flags AddExportOutputFlags registered.
func ReadExportOutput(cmd *cobra.Command) ExportOutput {
	file, _ := cmd.Flags().GetString("file")
	encrypt, _ := cmd.Flags().GetBool("encrypt")
	passphraseFile, _ := cmd.Flags().GetString("passphrase-file")
	force, _ := cmd.Flags().GetBool("force")
	return ExportOutput{File: file, Encrypt: encrypt, PassphraseFile: passphraseFile, Force: force}
}

// Check validates the output flags before anything is authorized or read.
// It returns nil when they are usable. Every message is a fixed phrase.
func (o ExportOutput) Check() *exportaudit.Failure {
	var msg string
	switch {
	case o.File == "":
		msg = "--file is required"
	case o.File == "-":
		msg = "--file - is not supported: an export is only ever written to a file"
	case !o.Encrypt && o.PassphraseFile != "":
		msg = "--passphrase-file was given with --encrypt=false: drop one, since a plaintext export has no passphrase"
	case !o.Force && pathExists(o.File):
		msg = outputExistsMessage
	default:
		return nil
	}
	f := exportaudit.BadRequest(msg)
	return &f
}

// pathExists reports whether anything, including a dangling symlink, is at
// path.
func pathExists(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}

// Passphrase resolves the sealing passphrase from --passphrase-file, then
// ROCKETVAULT_EXPORT_PASSPHRASE, then a terminal prompt asked twice, exactly
// as "secrets export" does. It returns "" when Encrypt is false. Call it only
// after authorization, so an unauthorized caller is never prompted.
func (o ExportOutput) Passphrase() (string, error) {
	if !o.Encrypt {
		return "", nil
	}
	passphrase, err := common.ResolvePassphrase(common.PassphraseSource{
		File:    o.PassphraseFile,
		EnvVar:  common.ExportPassphraseEnvVar,
		Prompt:  "Export passphrase: ",
		Confirm: true,
	})
	if errors.Is(err, common.ErrNoPassphraseAvailable) {
		return "", fmt.Errorf("export encryption is on but no passphrase is available: "+
			"pass --passphrase-file, set %s, or pass --encrypt=false to write plaintext deliberately",
			common.ExportPassphraseEnvVar)
	}
	if err != nil {
		return "", fmt.Errorf("failed to resolve export passphrase: %w", err)
	}
	return passphrase, nil
}

// Write seals p, or writes p.Content in the clear after printing warning to
// stderr, and moves the file into place atomically with mode 0600. warning
// completes the sentence "Warning: --encrypt=false — <file> ...".
func (o ExportOutput) Write(cmd *cobra.Command, p common.ItemExportPayload, passphrase, warning string) error {
	data := p.Content
	if o.Encrypt {
		sealed, err := common.SealItemExport(p, passphrase)
		if err != nil {
			return fmt.Errorf("failed to seal the export: %w", err)
		}
		data = sealed
	} else {
		fmt.Fprintf(cmd.ErrOrStderr(), "Warning: --encrypt=false — %s %s\n", o.File, warning) //nolint:errcheck
	}
	return common.WritePrivateFile(o.File, data, o.Force)
}

// PrintStatus writes the status block a successful export prints to stdout.
// It names the item and the file and never carries material.
func (o ExportOutput) PrintStatus(cmd *cobra.Command, label, name string, version int, format string) {
	encryption := "none (plaintext)"
	if o.Encrypt {
		encryption = "passphrase (argon2id + AES-256-GCM)"
	}
	fmt.Fprintf(cmd.OutOrStdout(), "%s exported successfully\nName: %s\nVersion: %d\nFormat: %s\nEncryption: %s\nFile: %s\n", //nolint:errcheck
		label, name, version, format, encryption, o.File)
}
