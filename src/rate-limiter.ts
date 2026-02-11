// Date: 2026-02-09
// File: src/rate-limiter.ts
// Purpose: In-memory sliding window rate limiter — zero KV writes
//
// Why in-memory instead of KV?
// - KV put() has daily limits (1k free, 1M paid) — rate limiting burns through them
// - KV is eventually consistent — not suitable for accurate counters
// - In-memory is ~0ms latency vs ~50ms for KV reads
//
// Trade-off: counters reset when the Worker isolate is evicted (typically every few minutes).
// This is acceptable for rate limiting because:
// - A brief reset is better than exhausting KV write quotas
// - Cloudflare Workers isolates persist across multiple requests
// - For strict global limits across all edge locations, use Durable Objects instead

interface RateLimitEntry {
  count: number;
  resetAt: number; // Unix timestamp in ms
}

// Module-level map persists across requests within the same Worker isolate
const rateLimitMap = new Map<string, RateLimitEntry>();

// Periodic cleanup to avoid unbounded memory growth
let lastCleanup = 0;
const CLEANUP_INTERVAL = 60_000; // 1 minute

function cleanupExpired(): void {
  const now = Date.now();
  if (now - lastCleanup < CLEANUP_INTERVAL) return;
  lastCleanup = now;
  for (const [key, entry] of rateLimitMap) {
    if (entry.resetAt <= now) {
      rateLimitMap.delete(key);
    }
  }
}

/**
 * Check rate limit using in-memory sliding window counter.
 * Returns { allowed: boolean, remaining: number, resetAt: number }
 */
export function checkRateLimit(
  key: string,
  limit: number,
  windowSeconds: number
): { allowed: boolean; remaining: number; resetAt: number } {
  cleanupExpired();

  const now = Date.now();
  const entry = rateLimitMap.get(key);

  // No existing entry or window expired — start fresh
  if (!entry || entry.resetAt <= now) {
    rateLimitMap.set(key, { count: 1, resetAt: now + windowSeconds * 1000 });
    return { allowed: true, remaining: limit - 1, resetAt: now + windowSeconds * 1000 };
  }

  // Within window — check limit
  if (entry.count >= limit) {
    return { allowed: false, remaining: 0, resetAt: entry.resetAt };
  }

  // Increment
  entry.count++;
  return { allowed: true, remaining: limit - entry.count, resetAt: entry.resetAt };
}
