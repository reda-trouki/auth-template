import { DomainEvent, DomainEventType } from "../domain/events";

export interface IClock { now(): Date }

export interface ICrypto {
  randomToken(bytes?: number): string;
  uuid(): string;
  sha256Hex(input: string): string;
  /** Constant-time comparison. Must return false (never throw) on length mismatch. */
  safeEqual(a: string, b: string): boolean;
}

export interface IPasswordHasher {
  hash(plain: string): Promise<string>;
  /** Must return false (never throw) for malformed stored hashes. */
  verify(plain: string, storedHash: string): Promise<boolean>;
}

export interface AccessTokenClaims {
  readonly sub: string;
  readonly roles: readonly string[];
  readonly sid: string; // session id the token was issued for
}
export interface VerifiedAccessToken extends AccessTokenClaims {
  readonly iat: number;
  readonly exp: number;
}

/** Throws TokenExpiredError / TokenInvalidError from verifyAccess. Never returns partial data. */
export interface ITokenService {
  signAccess(claims: AccessTokenClaims): Promise<{ token: string; expiresAt: Date }>;
  verifyAccess(token: string): Promise<VerifiedAccessToken>;
}

export type EventHandler = (event: DomainEvent) => void | Promise<void>;

export interface IEventBus {
  publish(event: DomainEvent): Promise<void>;
  subscribe(type: DomainEventType | "*", handler: EventHandler): () => void;
}

export interface ILogger {
  debug(message: string, meta?: unknown): void;
  info(message: string, meta?: unknown): void;
  warn(message: string, meta?: unknown): void;
  error(message: string, meta?: unknown): void;
}
