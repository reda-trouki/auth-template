import { Subject } from "../domain/entities";
import { TokenInvalidError } from "../domain/errors";
import { ISessionRepository } from "../ports/repositories";
import { ITokenService } from "../ports/services";

export interface AuthenticatedPrincipal { subject: Subject; sessionId: string }

export class AuthenticateToken {
  /**
   * strictSessionCheck=false (default): fully stateless, but a logged-out access token stays
   *   valid until it expires (keep accessTtl short).
   * strictSessionCheck=true: one session lookup per request; logout/revocation is immediate.
   */
  constructor(
    private readonly tokens: ITokenService,
    private readonly sessions: ISessionRepository,
    private readonly strictSessionCheck: boolean,
  ) {}

  async execute(input: { accessToken: string }): Promise<AuthenticatedPrincipal> {
    const claims = await this.tokens.verifyAccess(input.accessToken); // throws typed errors
    if (this.strictSessionCheck) {
      const session = await this.sessions.findById(claims.sid);
      if (!session || session.revokedAt || session.userId !== claims.sub) throw new TokenInvalidError("Session revoked");
    }
    return { subject: { id: claims.sub, roles: claims.roles }, sessionId: claims.sid };
  }
}
