package middleware

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

type fakeClock struct{ t time.Time }

func (f *fakeClock) now() time.Time          { return f.t }
func (f *fakeClock) advance(d time.Duration) { f.t = f.t.Add(d) }

func TestKeyedRateLimiter_EvictsIdleEntries(t *testing.T) {
	t.Parallel()
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	l := newKeyedRateLimiterWith(5, 1000, clk.now)
	for i := 0; i < 50; i++ {
		l.get(fmt.Sprintf("10.0.0.%d", i))
	}
	assert.Equal(t, 50, l.len())

	clk.advance(limiterIdleTTL + limiterSweepInterval)
	l.get("10.9.9.9") // Triggers the lazy sweep.
	assert.Equal(t, 1, l.len())
}

func TestKeyedRateLimiter_SweepKeepsActiveEntries(t *testing.T) {
	t.Parallel()
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	l := newKeyedRateLimiterWith(5, 1000, clk.now)
	active := l.get("active")
	l.get("idle")

	for i := 0; i < 4; i++ {
		clk.advance(limiterSweepInterval)
		assert.Same(t, active, l.get("active"), "a recently used bucket must survive sweeps")
	}
	assert.Equal(t, 1, l.len(), "only the idle entry is evicted")
}

func TestKeyedRateLimiter_CapEvictsOldest(t *testing.T) {
	t.Parallel()
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	l := newKeyedRateLimiterWith(5, 3, clk.now)
	l.get("a")
	clk.advance(time.Second)
	l.get("b")
	clk.advance(time.Second)
	l.get("c")
	clk.advance(time.Second)
	l.get("d") // Over the cap: "a" is the oldest.
	assert.Equal(t, 3, l.len())
	assert.NotContains(t, l.keys(), "a")
	assert.Contains(t, l.keys(), "d")
}

func TestKeyedRateLimiter_SameKeySameLimiter(t *testing.T) {
	t.Parallel()
	l := newKeyedRateLimiter(5)
	assert.Same(t, l.get("k"), l.get("k"))
}

func TestKeyedRateLimiter_CapEvictsLeastRecentlySeen(t *testing.T) {
	t.Parallel()
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	l := newKeyedRateLimiterWith(5, 3, clk.now)
	a := l.get("a")
	clk.advance(time.Second)
	l.get("b")
	clk.advance(time.Second)
	l.get("c")
	clk.advance(time.Second)
	assert.Same(t, a, l.get("a"), "touching a key refreshes its recency")
	clk.advance(time.Second)
	l.get("d") // Over the cap: "b" is now the least recently seen.
	assert.ElementsMatch(t, []string{"a", "c", "d"}, l.keys())
	assert.Same(t, a, l.get("a"), "the recently seen bucket keeps its state")
}

func TestKeyedRateLimiter_EvictedKeyStartsFresh(t *testing.T) {
	t.Parallel()
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	l := newKeyedRateLimiterWith(5, 1, clk.now)
	first := l.get("a")
	for i := 0; i < 5; i++ {
		first.Allow()
	}
	assert.False(t, first.Allow(), "the burst is spent")
	l.get("b") // Evicts "a" at the cap of one.
	again := l.get("a")
	assert.NotSame(t, first, again)
	assert.True(t, again.Allow(), "an evicted key comes back with a full burst")
}

func TestKeyedRateLimiter_ConcurrentAccessStaysBounded(t *testing.T) {
	t.Parallel()
	l := newKeyedRateLimiterWith(5, 64, time.Now)
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 500; i++ {
				l.get(fmt.Sprintf("%d-%d", g, i%100))
				_ = l.len()
			}
		}(g)
	}
	wg.Wait()
	assert.LessOrEqual(t, l.len(), 64)
}

func (l *keyedRateLimiter) keys() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]string, 0, len(l.entries))
	for k := range l.entries {
		out = append(out, k)
	}
	return out
}
