import express from "express";
import request from "supertest";
import { describe, expect, it } from "vitest";
import { allowWhen, any, hasRole, isOwner } from "../../src";
import { buildModule } from "../fakes/helpers";

function makeApp(over = {}) {
  const ctx = buildModule(over);
  const { auth } = ctx;
  const posts = new Map([["p1", { id: "p1", authorId: "" }]]);
  auth.resources.register("post", (id) => posts.get(id));
  auth.policies.register(allowWhen("post:update", any(isOwner("authorId"), hasRole("admin")), "post-owner-or-admin"));

  const app = express();
  app.use("/auth", auth.router);
  app.get("/admin", auth.authenticate(), auth.authorize("admin:read"), (_q, r) => { r.json({ ok: true }); });
  app.put("/posts/:id", auth.authenticate(), auth.authorize("post:update", { resource: { type: "post", idFrom: "params.id" } }), (_q, r) => { r.json({ ok: true }); });
  app.get("/crash", () => { throw new Error("secret internal detail: db password=hunter2"); });
  app.use(auth.notFoundHandler);
  app.use(auth.errorHandler);
  return { app, posts, ...ctx };
}

const body = { email: "bob@example.com", password: "correct-horse-battery" };
async function signup(app: express.Express) {
  await request(app).post("/auth/register").send(body).expect(201);
  const login = await request(app).post("/auth/login").send(body).expect(200);
  return login.body as { user: { id: string }; tokens: { accessToken: string; refreshToken: string } };
}

describe("HTTP flow", () => {
  it("register -> login -> /me -> refresh -> replay detected -> logout", async () => {
    const { app } = makeApp();
    const { tokens } = await signup(app);

    const me = await request(app).get("/auth/me").set("Authorization", `Bearer ${tokens.accessToken}`).expect(200);
    expect(me.body.user.email).toBe("bob@example.com");
    expect(JSON.stringify(me.body)).not.toMatch(/passwordHash|scrypt/);

    const r1 = await request(app).post("/auth/refresh").send({ refreshToken: tokens.refreshToken }).expect(200);
    await request(app).post("/auth/refresh").send({ refreshToken: tokens.refreshToken }).expect(401); // replay
    await request(app).post("/auth/refresh").send({ refreshToken: r1.body.tokens.refreshToken }).expect(401); // family burned
    await request(app).post("/auth/logout").send({ refreshToken: "whatever" }).expect(204);
  });

  it("registration cannot grant roles (mass assignment blocked)", async () => {
    const { app } = makeApp();
    await request(app).post("/auth/register").send({ ...body, roles: ["admin"] }).expect(400);
  });

  it("401 vs 403 vs 404 are distinct and correct", async () => {
    const { app } = makeApp();
    const { tokens } = await signup(app);
    await request(app).get("/admin").expect(401);
    await request(app).get("/admin").set("Authorization", "Bearer garbage").expect(401);
    await request(app).get("/admin").set("Authorization", "Basic abc").expect(401);
    const forbidden = await request(app).get("/admin").set("Authorization", `Bearer ${tokens.accessToken}`).expect(403);
    expect(forbidden.body.error.code).toBe("FORBIDDEN");
    await request(app).get("/nope").expect(404);
  });

  it("resource-based authorization: owner allowed, stranger denied, missing resource 404", async () => {
    const { app, posts } = makeApp();
    const { user, tokens } = await signup(app);
    const h = { Authorization: `Bearer ${tokens.accessToken}` };
    posts.set("p1", { id: "p1", authorId: user.id });
    posts.set("p2", { id: "p2", authorId: "someone-else" });
    await request(app).put("/posts/p1").set(h).expect(200);
    await request(app).put("/posts/p2").set(h).expect(403);
    await request(app).put("/posts/ghost").set(h).expect(404);
  });

  it("never leaks internals, and malformed/oversized bodies are clean 4xx", async () => {
    const { app } = makeApp();
    const crash = await request(app).get("/crash").expect(500);
    expect(JSON.stringify(crash.body)).not.toMatch(/hunter2|db password/);
    await request(app).post("/auth/login").set("Content-Type", "application/json").send("{bad json").expect(400);
    await request(app).post("/auth/login").send({ email: "a@b.co", password: "x".repeat(50_000) }).expect(413);
    await request(app).post("/auth/login").send({}).expect(400);
  });

  it("rate limits login by IP with Retry-After", async () => {
    const { app } = makeApp({ rateLimits: { login: { windowMs: 60_000, max: 3 } }, lockout: { maxAttempts: 100 } });
    for (let i = 0; i < 3; i++) await request(app).post("/auth/login").send({ email: "x@y.co", password: "wrong-wrong-wrong" }).expect(401);
    const res = await request(app).post("/auth/login").send({ email: "x@y.co", password: "wrong-wrong-wrong" }).expect(429);
    expect(res.headers["retry-after"]).toBeDefined();
  });

  it("responses are marked no-store", async () => {
    const { app } = makeApp();
    const res = await request(app).post("/auth/login").send({ email: "x@y.co", password: "wrong-wrong-wrong" });
    expect(res.headers["cache-control"]).toBe("no-store");
  });
});
