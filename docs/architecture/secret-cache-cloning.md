# Secret Cache: Clone-on-Get/Set Pattern

## What

`internal/cache/secret_cache.go`'s `SecretCache` stores `*model.Secret` and
returns/accepts **deep clones**, never the stored pointer itself, on both
`Get` and `Set`.

## Where

- `internal/cache/secret_cache.go`
  - `cloneSecret(s *model.Secret) *model.Secret` (lines 45–64) — the clone helper
  - `cloneTime(t *time.Time) *time.Time` (lines 66–73) — helper for the four `*time.Time` fields
  - `(c *SecretCache) Get(...)` — clones on read (line 117): `return cloneSecret(cached.Secret), true`
  - `(c *SecretCache) Set(...)` — clones on write (line 135): `c.cache[key] = &CachedSecret{Secret: cloneSecret(secret), ...}`
- `internal/cache/cache_integration.go` — `CachedSecretService.GetSecret` (lines 33–61) is the only caller of `SecretCache.Get`/`Set`; falls back to the wrapped `secrets.SecretService` on a miss and repopulates via `Set`.
- Constructed in `internal/container/service_container.go:527`: `cache.NewCachedSecretService(retryEnabledSecretService, c.secretCache, c.logger.Logger)`.
- Invalidation (not `Get`/`Set`) goes through `SecretCacheInvalidator` (`internal/services/secrets/cache_invalidator.go`), used by `rotation_service.go` and `versioning_service.go`; `*SecretCache` implements it via `DeleteByID`.

## Why cloning is necessary here

`model.Secret` (`model/secret.go:12-28`) has reference-type fields that a plain
`cp := *s` shallow copy would leave aliased to the original:

```go
type Secret struct {
    ...
    Tags             []string     // slice — shallow copy aliases the backing array
    DeletedAt        *time.Time   // pointer fields — shallow copy aliases the same time.Time
    ExpiresAt        *time.Time
    NotBefore        *time.Time
    ScheduledPurgeAt *time.Time
}
```

`cloneSecret` does the shallow copy, then explicitly deep-copies `Tags` and
each `*time.Time` pointer via `cloneTime`.

## The concrete failure mode this prevents

`api/secrets.go`'s `updateSecret` handler fetches a secret, then mutates the
returned pointer directly before persisting:

```go
secret, _ := secretService.GetSecret(ctx, ...)   // would be the cache's live pointer without cloning
secret.Name = req.Name
secret.Value = req.Value
secret.Tags = req.Tags
...
// persisted after this point
```

Without clone-on-Get, this mutates the cache entry *before* the update is
validated/persisted:
1. If the downstream write fails or is rejected, the cache is left reflecting
   an edit that was never actually saved — silent corruption.
2. A concurrent `GetSecret` (e.g. a GET racing this PUT) can observe a
   half-written secret — a data race on the `*Secret` payload itself, even
   though the map access is protected by `SecretCache`'s `sync.RWMutex`.

Clone-on-Set gives the same guarantee in the other direction: a caller that
keeps mutating the object it just passed to `Set` won't leak those later
edits into the cache.

## Cost / tradeoff

One allocation + slice copy per `Get` hit and per `Set`, in exchange for
"every caller owns an independent copy" as a hard invariant — no
shared-mutable-state bugs between cache entries and callers, or between
concurrent callers.

## How to apply elsewhere

Any new cache (or similar store-and-hand-back-a-pointer pattern) for a struct
with slice/map/pointer fields needs the same treatment if callers are
expected to mutate what they get back (as `updateSecret`-style handlers do).
Check `model.Key` / `model.Certificate` caches, if/when added, for the same
requirement — `KeyService`/`CertificateService` follow the same
fetch-then-mutate-then-persist pattern as secrets (see CLAUDE.md's Key/Certificate
Management sections).
