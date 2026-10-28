import type { NextFunction, Request, RequestHandler, Response } from "express";

/** Express 4 does not catch rejected promises; this makes the template safe on 4 and 5. */
export const asyncHandler =
  (fn: (req: Request, res: Response, next: NextFunction) => Promise<unknown>): RequestHandler =>
  (req, res, next) => { fn(req, res, next).catch(next); };
