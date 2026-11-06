package cmd

import (
	"slices"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// Every flag named in a command's Example block must actually be registered on
// that command, or inherited from an ancestor. Help text that invents a flag is
// worse than no help at all, since the reader copies it and gets an error.
//
// See docs/contributing/cli-help-conventions.md for the wider house style this guards.

// joinContinuations merges backslash-continued lines into single logical lines
// so that a wrapped invocation is validated as one command.
func joinContinuations(example string) []string {
	var lines []string
	var buf strings.Builder

	for raw := range strings.SplitSeq(example, "\n") {
		trimmed := strings.TrimSpace(raw)
		if cut, ok := strings.CutSuffix(trimmed, `\`); ok {
			buf.WriteString(cut)
			buf.WriteString(" ")
			continue
		}
		buf.WriteString(trimmed)
		lines = append(lines, buf.String())
		buf.Reset()
	}
	if buf.Len() > 0 {
		lines = append(lines, buf.String())
	}
	return lines
}

// exampleInvocations returns the logical lines of an Example block that are
// actual `rocketvault ...` invocations, skipping comments and blank lines.
func exampleInvocations(example string) []string {
	var out []string
	for _, line := range joinContinuations(example) {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if !strings.HasPrefix(line, "rocketvault ") {
			continue
		}
		out = append(out, line)
	}
	return out
}

// flagNames extracts the flag tokens from a tokenized invocation. Long flags
// are returned without the leading dashes and without any "=value" suffix;
// short flags are returned as single characters.
func flagNames(tokens []string) (long []string, short []string) {
	for _, tok := range tokens {
		switch {
		case tok == "--":
			return long, short
		case strings.HasPrefix(tok, "--"):
			name := strings.TrimPrefix(tok, "--")
			if i := strings.Index(name, "="); i >= 0 {
				name = name[:i]
			}
			if name != "" {
				long = append(long, name)
			}
		case strings.HasPrefix(tok, "-") && len(tok) > 1:
			// A short flag cluster such as -it; validate each character.
			for _, r := range tok[1:] {
				if r == '=' {
					break
				}
				short = append(short, string(r))
			}
		}
	}
	return long, short
}

// hasFlag reports whether name resolves on cmd, counting inherited and
// persistent flags the way cobra does at parse time.
func hasFlag(cmd *cobra.Command, name string) bool {
	if cmd.Flags().Lookup(name) != nil {
		return true
	}
	if cmd.PersistentFlags().Lookup(name) != nil {
		return true
	}
	return cmd.InheritedFlags().Lookup(name) != nil
}

func hasShorthand(cmd *cobra.Command, sh string) bool {
	if cmd.Flags().ShorthandLookup(sh) != nil {
		return true
	}
	if cmd.PersistentFlags().ShorthandLookup(sh) != nil {
		return true
	}
	return cmd.InheritedFlags().ShorthandLookup(sh) != nil
}

// walk visits cmd and every descendant.
func walk(cmd *cobra.Command, visit func(*cobra.Command)) {
	visit(cmd)
	for _, child := range cmd.Commands() {
		walk(child, visit)
	}
}

func TestExampleFlagsAreRegistered(t *testing.T) {
	walk(rootCmd, func(cmd *cobra.Command) {
		if cmd.Example == "" {
			return
		}
		for _, line := range exampleInvocations(cmd.Example) {
			tokens := strings.Fields(line)
			if len(tokens) < 2 {
				continue
			}

			// Resolve which command this invocation actually targets, using
			// cobra's own resolution so subcommand paths are handled the same
			// way they are at runtime.
			target, _, err := rootCmd.Find(tokens[1:])
			if err != nil || target == nil {
				t.Errorf("%s: example does not resolve to a command: %q", cmd.CommandPath(), line)
				continue
			}

			long, short := flagNames(tokens[1:])
			for _, name := range long {
				if !hasFlag(target, name) {
					t.Errorf("%s: example uses --%s, which is not registered on %q\n  line: %s",
						cmd.CommandPath(), name, target.CommandPath(), line)
				}
			}
			for _, sh := range short {
				if !hasShorthand(target, sh) {
					t.Errorf("%s: example uses -%s, which is not registered on %q\n  line: %s",
						cmd.CommandPath(), sh, target.CommandPath(), line)
				}
			}
		}
	})
}

// Leaf commands must not teach per-invocation credentials; the CLI caches
// sessions. The login command itself is exempt, as are the group aggregators
// that carry the single canonical login line.
func TestLeafExamplesDoNotShowCredentials(t *testing.T) {
	credFlags := []string{"password", "totp-code"}

	walk(rootCmd, func(cmd *cobra.Command) {
		if cmd.Example == "" || cmd.HasSubCommands() {
			return // group aggregators carry the login line by design
		}
		if cmd.Name() == "login" || cmd.Name() == "admin" {
			return
		}
		for _, line := range exampleInvocations(cmd.Example) {
			long, _ := flagNames(strings.Fields(line))
			for _, name := range long {
				if slices.Contains(credFlags, name) {
					t.Errorf("%s: leaf example shows --%s; sessions are cached, see docs/contributing/cli-help-conventions.md\n  line: %s",
						cmd.CommandPath(), name, line)
				}
			}
		}
	})
}

// Remote mode is rejected by persistentPreRun for everything outside the
// context group, so advertising these flags elsewhere documents an error path.
// mcp is the other exception: it replaces persistentPreRun entirely, since a
// remote target is its normal operating mode, not an edge case.
func TestExamplesDoNotAdvertiseUnsupportedRemoteFlags(t *testing.T) {
	remoteFlags := []string{"server", "ca-cert", "insecure-skip-verify"}

	walk(rootCmd, func(cmd *cobra.Command) {
		if cmd.Example == "" {
			return
		}
		if cmd.Name() == "context" || (cmd.Parent() != nil && cmd.Parent().Name() == "context") {
			return
		}
		if cmd.Name() == "mcp" {
			return
		}
		for _, line := range exampleInvocations(cmd.Example) {
			long, _ := flagNames(strings.Fields(line))
			for _, name := range long {
				if slices.Contains(remoteFlags, name) {
					t.Errorf("%s: example advertises --%s, which persistentPreRun rejects for this command\n  line: %s",
						cmd.CommandPath(), name, line)
				}
			}
		}
	})
}
