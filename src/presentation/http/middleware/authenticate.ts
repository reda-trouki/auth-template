import type { RequestHandler } from "express";
import { TokenInvalidError, UnauthenticatedError } from "../../../core/domain/errors";
import { AuthenticateToken } from "../../../core/use-cases/AuthenticateToken";
import { asyncHandler } from "./asyncHandler";

const BEARER = /^Bearer\s+([A-Za-z0-9\-._~+/]+=*)$/i;

export function createAuthenticate(useCase: AuthenticateToken): RequestHandler {
  return asyncHandler(async (req, _res, next) => {
    const header = req.headers.authorization;
    if (!header) throw new UnauthenticatedError();
    const match = BEARER.exec(header);
    if (!match || !match[1]) throw new TokenInvalidError();
    const principal = await useCase.execute({ accessToken: match[1] });
    req.auth = { subject: principal.subject, sessionId: principal.sessionId };
    next();
  });
}
