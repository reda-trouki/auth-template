import { createAuthModule, AuthModuleOptions, noopLogger, ScryptPasswordHasher, IClock } from "../../src";

export class MutableClock implements IClock {
  constructor(private t = new Date("2026-01-01T00:00:00Z")) {}
  now(): Date { return new Date(this.t); }
  advance(seconds: number): void { this.t = new Date(this.t.getTime() + seconds * 1000); }
}

export const SECRET = "test-secret-test-secret-test-secret-123456";

export function buildModule(overrides: Partial<AuthModuleOptions> = {}) {
  const clock = new MutableClock();
  const auth = createAuthModule({
    jwt: { secret: SECRET },
    clock,
    logger: noopLogger,
    hasher: new ScryptPasswordHasher({ N: 1024 }), // cheap cost: tests only
    ...overrides,
  });
  return { auth, clock };
}

export const CREDS = { email: "Alice@Example.com", password: "correct-horse-battery" };
