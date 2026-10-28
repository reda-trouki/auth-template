import type { ErrorRequestHandler, RequestHandler } from "express";
import { ZodError } from "zod";
import {
  AccountLockedError, AppError, InternalError, PayloadTooLargeError, ResourceNotFoundError,
  TooManyRequestsError, ValidationError,
} from "../../../core/domain/errors";
import { ILogger } from "../../../core/ports/services";

/** Converts ANY thrown value into an AppError. Unknown errors become opaque InternalErrors. */
export function toAppError(err: unknown): AppError {
  if (err instanceof AppError) return err;
  if (err instanceof ZodError) {
    return new ValidationError("Invalid request", err.issues.map((i) => ({ path: i.path.join("."), message: i.message })));
  }
  const e = err as { type?: string } | null;
  if (e?.type === "entity.parse.failed") return new ValidationError("Malformed JSON body");
  if (e?.type === "entity.too.large") return new PayloadTooLargeError();
  return new InternalError("Unhandled error", err);
}

export function createErrorHandler(logger: ILogger): ErrorRequestHandler {
  // 4 args are required: Express identifies error middleware by arity.
  return (err, _req, res, next) => {
    if (res.headersSent) return next(err);
    const app = toAppError(err);
    if (!app.expose) logger.error("Unhandled error", { err: err instanceof Error ? err.stack : String(err) });

    if (app instanceof TooManyRequestsError || app instanceof AccountLockedError) {
      res.setHeader("Retry-After", String(app.retryAfterSeconds));
    }
    res.status(app.httpStatus).json({
      error: {
        code: app.code,
        message: app.expose ? app.message : "Internal server error", // never leak internals
        ...(app.expose && app.details ? { details: app.details } : {}),
      },
    });
  };
}

export const notFoundHandler: RequestHandler = (_req, _res, next) => next(new ResourceNotFoundError("Route not found"));
