import type { Request, RequestHandler } from "express";
import { TooManyRequestsError } from "../../../core/domain/errors";

export interface IRateLimitStore {
  /** Count a hit for `key`; returns the running count in the current window. */
  hit(key: string, windowMs: number): Promise<{ count: number; resetAt: number }>;
}

/** Fixed-window, bounded-memory store. Single process only: use a Redis-backed store when you scale out. */
export class InMemoryRateLimitStore implements IRateLimitStore {
  private readonly buckets = new Map<string, { count: number; resetAt: number }>();
  constructor(private readonly maxKeys = 50_000, private readonly now: () => number = Date.now) {}

  async hit(key: string, windowMs: number) {
    const t = this.now();
    let b = this.buckets.get(key);
    if (!b || b.resetAt <= t) {
      if (this.buckets.size >= this.maxKeys) this.evict(t);
      b = { count: 0, resetAt: t + windowMs };
      this.buckets.set(key, b);
    }
    b.count++;
    return { count: b.count, resetAt: b.resetAt };
  }

  private evict(t: number): void {
    for (const [k, v] of this.buckets) if (v.resetAt <= t) this.buckets.delete(k);
    // Still full (attack): drop oldest entries so memory stays bounded.
    while (this.buckets.size >= this.maxKeys) {
      const first = this.buckets.keys().next().value;
      if (first === undefined) break;
      this.buckets.delete(first);
    }
  }
}

export interface RateLimitOptions {
  store: IRateLimitStore;
  windowMs: number;
  max: number;
  name: string;
  keyFn?: (req: Request) => string;
}

export function rateLimit(opts: RateLimitOptions): RequestHandler {
  const keyFn = opts.keyFn ?? ((req) => req.ip ?? "unknown");
  return (req, _res, next) => {
    opts.store.hit(`${opts.name}:${keyFn(req)}`, opts.windowMs).then(
      ({ count, resetAt }) => {
        if (count > opts.max) return next(new TooManyRequestsError(Math.max(1, Math.ceil((resetAt - Date.now()) / 1000))));
        next();
      },
      // Store outage: fail OPEN for availability (login still has per-account lockout as a second layer).
      () => next(),
    );
  };
}
