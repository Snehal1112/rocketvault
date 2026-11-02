import { QueryClient } from "@tanstack/react-query"

import { ApiError } from "@/api/types"

// A query gets at most this many retries beyond the initial attempt.
const MAX_QUERY_RETRIES = 2

/**
 * Decides whether TanStack Query should retry a failed query.
 *
 * A response carrying a `retry_after_seconds` hint (a tripped circuit
 * breaker or an explicit rate limit) is never retried automatically -- see
 * the design doc's API client section: the UI surfaces a toast and lets the
 * caller retry manually instead of hammering a backend that just asked for
 * backoff. Any other 4xx is a client error a retry cannot fix. Everything
 * else (network failures, 5xx) gets a small bounded number of retries.
 */
export function shouldRetry(failureCount: number, error: unknown): boolean {
  if (error instanceof ApiError) {
    if (error.retryAfterSeconds && error.retryAfterSeconds > 0) {
      return false
    }
    if (error.statusCode >= 400 && error.statusCode < 500) {
      return false
    }
  }

  return failureCount < MAX_QUERY_RETRIES
}

export const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: shouldRetry,
    },
    mutations: {
      // Mutations are user-initiated writes; retrying them silently risks a
      // duplicate side effect, so failures surface immediately instead.
      retry: false,
    },
  },
})
