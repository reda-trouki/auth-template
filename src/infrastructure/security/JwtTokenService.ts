import jwt from "jsonwebtoken";
import { z } from "zod";
import { TokenExpiredError, TokenInvalidError } from "../../core/domain/errors";
import {
  AccessTokenClaims, IClock, ITokenService, VerifiedAccessToken,
} from "../../core/ports/services";

export interface JwtConfig { secret: string; issuer: string; audience: string; accessTtlSeconds: number }

const PayloadSchema = z.object({
  sub: z.string().min(1),
  sid: z.string().min(1),
  roles: z.array(z.string()),
  iat: z.number(),
  exp: z.number(),
});

/**
 * Adapter around `jsonwebtoken`. Hardening:
 *  - algorithm pinned to HS256 on BOTH sign and verify (blocks "alg: none" / algorithm confusion)
 *  - issuer + audience enforced
 *  - payload shape validated after signature check (a valid signature is not a valid shape)
 *  - time comes from the injected clock, so expiry is testable
 */
export class JwtTokenService implements ITokenService {
  constructor(private readonly cfg: JwtConfig, private readonly clock: IClock) {}

  async signAccess(claims: AccessTokenClaims): Promise<{ token: string; expiresAt: Date }> {
    const iat = Math.floor(this.clock.now().getTime() / 1000);
    const exp = iat + this.cfg.accessTtlSeconds;
    const token = jwt.sign(
      { sub: claims.sub, sid: claims.sid, roles: [...claims.roles], iat, exp, iss: this.cfg.issuer, aud: this.cfg.audience },
      this.cfg.secret,
      { algorithm: "HS256" },
    );
    return { token, expiresAt: new Date(exp * 1000) };
  }

  async verifyAccess(token: string): Promise<VerifiedAccessToken> {
    if (typeof token !== "string" || token.length === 0 || token.length > 4096) throw new TokenInvalidError();
    let decoded: unknown;
    try {
      decoded = jwt.verify(token, this.cfg.secret, {
        algorithms: ["HS256"],
        issuer: this.cfg.issuer,
        audience: this.cfg.audience,
        clockTimestamp: Math.floor(this.clock.now().getTime() / 1000),
      });
    } catch (err) {
      if (err instanceof jwt.TokenExpiredError) throw new TokenExpiredError("Access token expired");
      throw new TokenInvalidError();
    }
    const parsed = PayloadSchema.safeParse(decoded);
    if (!parsed.success) throw new TokenInvalidError();
    return parsed.data;
  }
}
