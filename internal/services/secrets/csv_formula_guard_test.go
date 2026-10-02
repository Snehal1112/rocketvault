package secrets

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCSVFormulaGuard_PrefixesTriggers(t *testing.T) {
	t.Parallel()
	for _, s := range []string{"=1+1", "+cmd", "-2", "@SUM(A1)", "\tx", "'quoted"} {
		assert.Equal(t, "'"+s, csvFormulaGuard(s), s)
	}
	for _, s := range []string{"", "plain", "a=b", "1-2"} {
		assert.Equal(t, s, csvFormulaGuard(s), s)
	}
}

func TestCSVFormulaGuard_RoundTrips(t *testing.T) {
	t.Parallel()
	for _, s := range []string{"", "=cmd|' /C calc'!A0", "-secret", "'already", "''two", "@x", "plain", "\tx", "+1"} {
		assert.Equal(t, s, csvFormulaUnguard(csvFormulaGuard(s)), s)
	}
}
