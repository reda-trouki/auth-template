import { ValidationError } from "./errors";

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

/** Single source of truth for email normalization. Used before every lookup/insert. */
export function normalizeEmail(raw: unknown): string {
  if (typeof raw !== "string") throw new ValidationError("Email must be a string");
  const email = raw.trim().toLowerCase();
  if (email.length === 0 || email.length > 254 || !EMAIL_RE.test(email)) {
    throw new ValidationError("Email is not valid");
  }
  return email;
}

/**
 * maxLength matters for security, not just UX: hashing is deliberately expensive,
 * so unbounded passwords are a CPU denial-of-service vector.
 */
export class PasswordPolicy {
  constructor(readonly minLength = 10, readonly maxLength = 128) {}

  assertValid(password: unknown): asserts password is string {
    if (typeof password !== "string") throw new ValidationError("Password must be a string");
    if (password.length < this.minLength) {
      throw new ValidationError(`Password must be at least ${this.minLength} characters`);
    }
    if (password.length > this.maxLength) {
      throw new ValidationError(`Password must be at most ${this.maxLength} characters`);
    }
    if (password.trim().length === 0) throw new ValidationError("Password cannot be blank");
  }

  /** Cheap guard for login: reject absurd inputs before spending CPU hashing them. */
  isWithinBounds(password: unknown): password is string {
    return typeof password === "string" && password.length > 0 && password.length <= this.maxLength;
  }
}

export const addSeconds = (d: Date, s: number): Date => new Date(d.getTime() + s * 1000);
export const secondsBetween = (from: Date, to: Date): number =>
  Math.max(0, Math.ceil((to.getTime() - from.getTime()) / 1000));
