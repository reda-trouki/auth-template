export type UserStatus = "active" | "suspended";

export interface User {
  readonly id: string;
  readonly email: string; // always normalized (trim + lowercase)
  readonly passwordHash: string;
  readonly roles: readonly string[];
  readonly status: UserStatus;
  readonly failedLoginAttempts: number;
  readonly lockedUntil: Date | null;
  readonly createdAt: Date;
  readonly updatedAt: Date;
}

/** What is safe to return to a client. passwordHash must never leave the core. */
export interface PublicUser {
  readonly id: string;
  readonly email: string;
  readonly roles: readonly string[];
  readonly status: UserStatus;
  readonly createdAt: Date;
}

export const toPublicUser = (u: User): PublicUser => ({
  id: u.id, email: u.email, roles: [...u.roles], status: u.status, createdAt: u.createdAt,
});

/**
 * One row per refresh token. Tokens rotate: each use creates a new Session in the
 * same family. Presenting an already-used token = theft signal => revoke the family.
 */
export interface Session {
  readonly id: string;
  readonly userId: string;
  readonly familyId: string;
  readonly secretHash: string; // sha256 of the secret part; raw secret is never stored
  readonly createdAt: Date;
  readonly expiresAt: Date;
  readonly familyExpiresAt: Date; // absolute cap: rotation can never extend past this
  readonly usedAt: Date | null;
  readonly revokedAt: Date | null;
}

export interface TokenPair {
  readonly accessToken: string;
  readonly accessTokenExpiresAt: Date;
  readonly refreshToken: string;
  readonly refreshTokenExpiresAt: Date;
}

export interface AuthResult {
  readonly user: PublicUser;
  readonly tokens: TokenPair;
}

/** Who is acting. Built from a verified access token. */
export interface Subject {
  readonly id: string;
  readonly roles: readonly string[];
  readonly attributes?: Record<string, unknown>;
}
