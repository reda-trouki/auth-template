import { ISessionRepository } from "../ports/repositories";
import { IClock, ICrypto, IEventBus } from "../ports/services";
import { REFRESH_TOKEN_SEPARATOR } from "../services/TokenIssuer";

export class LogoutUser {
  constructor(
    private readonly sessions: ISessionRepository,
    private readonly crypto: ICrypto,
    private readonly clock: IClock,
    private readonly events: IEventBus,
  ) {}

  /** Idempotent and silent: logging out with a bad/expired token is not an error. */
  async execute(input: { refreshToken: string }): Promise<void> {
    const token = input.refreshToken;
    if (typeof token !== "string" || token.length > 512) return;
    const idx = token.indexOf(REFRESH_TOKEN_SEPARATOR);
    if (idx <= 0) return;

    const session = await this.sessions.findById(token.slice(0, idx));
    if (!session) return;
    if (!this.crypto.safeEqual(session.secretHash, this.crypto.sha256Hex(token.slice(idx + 1)))) return;

    const now = this.clock.now();
    await this.sessions.revokeFamily(session.familyId, now);
    await this.events.publish({ type: "LoggedOut", userId: session.userId, familyId: session.familyId, occurredAt: now });
  }

  async executeAll(input: { userId: string }): Promise<void> {
    const now = this.clock.now();
    await this.sessions.revokeAllForUser(input.userId, now);
    await this.events.publish({ type: "LoggedOut", userId: input.userId, occurredAt: now });
  }
}
