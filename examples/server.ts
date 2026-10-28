/**
 * Run: JWT_SECRET=$(openssl rand -base64 48) npm run dev
 * Shows the whole integration surface a host project needs.
 */
import express from "express";
import { allowWhen, any, createAuthModule, hasRole, isOwner } from "../src";

const auth = createAuthModule({
  jwt: { secret: process.env.JWT_SECRET ?? "dev-only-secret-dev-only-secret-0123456789" },
  roles: {
    user: { permissions: ["profile:*", "post:create", "post:read"] },
    editor: { permissions: ["post:*"], inherits: ["user"] },
    admin: { permissions: ["*"], inherits: ["editor"] },
  },
  // userRepository / sessionRepository: pass your own (Prisma, Mongo, ...) for production.
});

// 1) Teach the library how to load a resource (needed for ownership checks)
const posts = new Map([["1", { id: "1", authorId: "someone" }]]);
auth.resources.register("post", (id) => posts.get(id));

// 2) Add your own business rule: only the author or an admin may update a post
auth.policies.register(allowWhen("post:update", any(isOwner("authorId"), hasRole("admin")), "post-owner-or-admin"));

// 3) React to security events (audit log, alerting, emails...)
auth.events.subscribe("RefreshTokenReuseDetected", (e) => console.warn("POSSIBLE TOKEN THEFT", e));

// 4) Seed the first admin (trusted code path; HTTP can never set roles)
auth.useCases.registerUser
  .execute({ email: "admin@example.com", password: "change-me-please-123", roles: ["admin"] })
  .catch(() => {});

const app = express();
app.set("trust proxy", 1); // set correctly behind a proxy, or rate limiting sees only the proxy IP
app.use("/auth", auth.router);
app.put("/posts/:id", auth.authenticate(),
  auth.authorize("post:update", { resource: { type: "post", idFrom: "params.id" } }),
  (_req, res) => { res.json({ updated: true }); });
app.get("/admin/stats", auth.authenticate(), auth.authorize("admin:read"), (_req, res) => { res.json({ users: 42 }); });

app.use(auth.notFoundHandler);
app.use(auth.errorHandler); // keep last
app.listen(3000, () => console.log("http://localhost:3000"));
