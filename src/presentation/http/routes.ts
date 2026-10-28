import express, { Router, RequestHandler } from "express";
import { AuthController } from "./controllers/AuthController";
import { asyncHandler } from "./middleware/asyncHandler";
import { rateLimit, IRateLimitStore } from "./middleware/rateLimit";

export interface RouterDeps {
  controller: AuthController;
  authenticate: RequestHandler;
  errorHandler: express.ErrorRequestHandler;
  rateLimitStore: IRateLimitStore;
  limits: {
    login: { windowMs: number; max: number };
    register: { windowMs: number; max: number };
    refresh: { windowMs: number; max: number };
  };
  bodyLimit: string;
}

export function buildRouter(d: RouterDeps): Router {
  const r = Router();
  r.use(express.json({ limit: d.bodyLimit })); // small cap: auth payloads are tiny
  r.use((_req, res, next) => { res.setHeader("Cache-Control", "no-store"); next(); }); // never cache tokens

  const limit = (name: keyof RouterDeps["limits"]) => rateLimit({ store: d.rateLimitStore, name, ...d.limits[name] });
  const c = d.controller;

  r.post("/register", limit("register"), asyncHandler(c.register));
  r.post("/login", limit("login"), asyncHandler(c.login));
  r.post("/refresh", limit("refresh"), asyncHandler(c.refresh));
  r.post("/logout", asyncHandler(c.logout));
  r.post("/logout-all", d.authenticate, asyncHandler(c.logoutAll));
  r.post("/change-password", d.authenticate, asyncHandler(c.changePasswordHandler));
  r.get("/me", d.authenticate, asyncHandler(c.me));

  r.use(d.errorHandler); // errors inside the auth router are always formatted safely
  return r;
}
