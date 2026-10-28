import type { Request, RequestHandler } from "express";
import { UnauthenticatedError, ValidationError } from "../../../core/domain/errors";
import { AuthorizationContext } from "../../../core/ports/IAuthorizationPolicy";
import { IClock } from "../../../core/ports/services";
import { PolicyEngine } from "../../../authorization/PolicyEngine";
import { ResourceLoaderRegistry } from "../../../authorization/ResourceLoaderRegistry";
import { asyncHandler } from "./asyncHandler";

export interface AuthorizeOptions {
  resource?: {
    type: string;
    /** "params.id" style path (params | query | body | headers) or a custom extractor. */
    idFrom: string | ((req: Request) => string | undefined);
  };
}

const ROOTS = new Set(["params", "query", "body"]);

function readPath(req: Request, path: string): string | undefined {
  const [root, ...rest] = path.split(".");
  if (!root || !ROOTS.has(root)) return undefined;
  let cur: unknown = (req as unknown as Record<string, unknown>)[root];
  for (const key of rest) {
    if (typeof cur !== "object" || cur === null || !Object.prototype.hasOwnProperty.call(cur, key)) return undefined;
    cur = (cur as Record<string, unknown>)[key];
  }
  return typeof cur === "string" || typeof cur === "number" ? String(cur) : undefined;
}

export function createAuthorize(engine: PolicyEngine, resources: ResourceLoaderRegistry, clock: IClock) {
  return (action: string, options: AuthorizeOptions = {}): RequestHandler =>
    asyncHandler(async (req, _res, next) => {
      if (!req.auth) throw new UnauthenticatedError(); // authorize() before authenticate() => safe 401, not a crash

      let resource: AuthorizationContext["resource"];
      if (options.resource) {
        const { type, idFrom } = options.resource;
        const id = typeof idFrom === "function" ? idFrom(req) : readPath(req, idFrom);
        if (!id) throw new ValidationError("Missing resource identifier");
        resource = { type, id, data: await resources.load(type, id) };
      }

      await engine.assert({
        subject: { ...req.auth.subject },
        action,
        resource,
        environment: { ip: req.ip, time: clock.now() },
      });
      next();
    });
}
