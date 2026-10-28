import { AuthResult, Session, toPublicUser } from "../domain/entities";
import { TokenExpiredError, TokenInvalidError } from "../domain/errors";
import { IUserRepository, ISessionRepository } from "../ports/repositories";
import { IClock, ICrypto, IEventBus } from "../ports/services";
import { REFRESH_TOKEN_SEPARATOR, TokenIssuer } from "../services/TokenIssuer";

export class RefreshSession {
  constructor(
    private readonly sessions: ISessionRepository,
    private readonly users: IUserRepository,
    private readonly issuer: TokenIssuer,
    private readonly crypto: ICrypto,
    private readonly clock: IClock,
    private readonly events: IEventBus,
  ) {}

  async execute(input: { refreshToken: string }): Promise<AuthResult> {
    const session = await this.authenticateToken(input.refreshToken);
    const now = this.clock.now();

    if (session.revokedAt) throw new TokenInvalidError();
    if (session.expiresAt <= now || session.familyExpiresAt <= now) throw new TokenExpiredError("Refresh token expired");

    // Atomic single-use. Loser of a race, or a replay of an old token, gets `false`.
    const consumed = !session.usedAt && (await this.sessions.consume(session.id, now));
    if (!consumed) {
      // A used token was presented again => likely stolen. Kill the whole family (attacker AND victim
      // must re-authenticate), and emit an event so the host can alert.
      await this.sessions.revokeFamily(session.familyId, now);
      await this.events.publish({
        type: "RefreshTokenReuseDetected", userId: session.userId, familyId: session.familyId, occurredAt: now,
      });
      throw new TokenInvalidError();
    }

    const user = await this.users.findById(session.userId);
    if (!user || user.status !== "active") {
      await this.sessions.revokeFamily(session.familyId, now);
      throw new TokenInvalidError();
    }

    const tokens = await this.issuer.issue(user, {
      familyId: session.familyId,
      familyExpiresAt: session.familyExpiresAt,
    });
    return { user: toPublicUser(user), tokens };
  }

  /** Parses and verifies `<sessionId>.<secret>`. Every failure mode collapses to TokenInvalidError. */
  private async authenticateToken(token: unknown): Promise<Session> {
    if (typeof token !== "string" || token.length > 512) throw new TokenInvalidError();
    const idx = token.indexOf(REFRESH_TOKEN_SEPARATOR);
    if (idx <= 0 || idx === token.length - 1) throw new TokenInvalidError();

    const session = await this.sessions.findById(token.slice(0, idx));
    // Compare against a dummy when missing so both paths do equal work.
    const expected = session?.secretHash ?? this.crypto.sha256Hex("missing");
    const presented = this.crypto.sha256Hex(token.slice(idx + 1));
    const matches = this.crypto.safeEqual(expected, presented);
    if (!session || !matches) throw new TokenInvalidError();
    return session;
  }
}
