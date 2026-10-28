import { TokenPair, User } from "../domain/entities";
import { addSeconds } from "../domain/validation";
import { ISessionRepository } from "../ports/repositories";
import { IClock, ICrypto, ITokenService } from "../ports/services";

export interface TokenIssuerConfig {
  refreshTtlSeconds: number;
  /** Hard ceiling for a whole rotation family, so a stolen-but-rotating token cannot live forever. */
  absoluteSessionTtlSeconds: number;
}

export interface SessionFamily { familyId: string; familyExpiresAt: Date }

export const REFRESH_TOKEN_SEPARATOR = ".";

/** Single place that mints sessions + token pairs. Used by Login and Refresh (DRY, one reason to change). */
export class TokenIssuer {
  constructor(
    private readonly sessions: ISessionRepository,
    private readonly tokens: ITokenService,
    private readonly crypto: ICrypto,
    private readonly clock: IClock,
    private readonly config: TokenIssuerConfig,
  ) {}

  async issue(user: User, family?: SessionFamily): Promise<TokenPair> {
    const now = this.clock.now();
    const familyId = family?.familyId ?? this.crypto.uuid();
    const familyExpiresAt = family?.familyExpiresAt ?? addSeconds(now, this.config.absoluteSessionTtlSeconds);
    const naturalExpiry = addSeconds(now, this.config.refreshTtlSeconds);
    const expiresAt = naturalExpiry < familyExpiresAt ? naturalExpiry : familyExpiresAt;

    const sessionId = this.crypto.uuid();
    const secret = this.crypto.randomToken(32);

    await this.sessions.create({
      id: sessionId, userId: user.id, familyId,
      secretHash: this.crypto.sha256Hex(secret),
      createdAt: now, expiresAt, familyExpiresAt, usedAt: null, revokedAt: null,
    });

    const access = await this.tokens.signAccess({ sub: user.id, roles: user.roles, sid: sessionId });
    return {
      accessToken: access.token,
      accessTokenExpiresAt: access.expiresAt,
      refreshToken: `${sessionId}${REFRESH_TOKEN_SEPARATOR}${secret}`,
      refreshTokenExpiresAt: expiresAt,
    };
  }
}
