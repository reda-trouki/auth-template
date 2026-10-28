import { describe, expect, it } from "vitest";
import {
  abstain, all, allow, allowWhen, any, AuthorizationContext, definePolicy, deny, denyWhen, DenyOverrides,
  FirstApplicable, ForbiddenError, hasRole, InMemoryRoleRegistry, isOwner, matchesAction, not, ConfigError, ResourceNotFoundError,
  AllowOverrides,
} from "../../src";
import { buildModule } from "../fakes/helpers";

const ctx = (over: Partial<AuthorizationContext> = {}): AuthorizationContext => ({
  subject: { id: "u1", roles: ["user"] }, action: "post:update", ...over,
});

describe("action matching", () => {
  it("handles exact, prefix wildcard and global wildcard", () => {
    expect(matchesAction("*", "a:b")).toBe(true);
    expect(matchesAction("post:*", "post:update")).toBe(true);
    expect(matchesAction("post:*", "postx:update")).toBe(false);
    expect(matchesAction("post:update", "post:update")).toBe(true);
    expect(matchesAction("post:update", "post:delete")).toBe(false);
  });
});

describe("PolicyEngine (fail closed)", () => {
  it("denies by default when nothing allows", async () => {
    const { auth } = buildModule();
    expect((await auth.engine.decide(ctx())).effect).toBe("deny");
  });
  it("RBAC allows via role permission and inheritance", async () => {
    const { auth } = buildModule();
    expect((await auth.engine.decide(ctx({ action: "profile:read" }))).effect).toBe("allow");
    expect((await auth.engine.decide(ctx({ subject: { id: "a", roles: ["admin"] }, action: "anything:at-all" }))).effect).toBe("allow");
    expect((await auth.engine.decide(ctx({ action: "billing:read" }))).effect).toBe("deny");
  });
  it("a policy that THROWS counts as deny and never crashes the request", async () => {
    const { auth } = buildModule();
    auth.policies.register(definePolicy("profile:*", () => { throw new Error("boom"); }, "buggy"));
    expect((await auth.engine.decide(ctx({ action: "profile:read" }))).effect).toBe("deny"); // deny overrides RBAC allow
  });
  it("a policy that never resolves is cut off by the timeout", async () => {
    const { auth } = buildModule({ policyTimeoutMs: 50 });
    auth.policies.register(definePolicy("profile:*", () => new Promise(() => {}), "hangs"));
    expect((await auth.engine.decide(ctx({ action: "profile:read" }))).effect).toBe("deny");
  });
  it("a malformed decision is a deny (typos cannot become allows)", async () => {
    const { auth } = buildModule();
    auth.policies.register(definePolicy("x:*", (() => ({ effect: "ALLOW" })) as never, "typo"));
    expect((await auth.engine.decide(ctx({ action: "x:y", subject: { id: "a", roles: ["admin"] } }))).effect).toBe("deny");
  });
  it("invalid contexts are denied", async () => {
    const { auth } = buildModule();
    expect((await auth.engine.decide({ subject: { id: "", roles: [] }, action: "" })).effect).toBe("deny");
    expect((await auth.engine.decide(undefined as never)).effect).toBe("deny");
  });
  it("assert() throws a generic ForbiddenError (reason stays server-side)", async () => {
    const { auth } = buildModule();
    const err = await auth.engine.assert(ctx()).catch((e) => e);
    expect(err).toBeInstanceOf(ForbiddenError);
    expect(err.message).not.toMatch(/policy/i);
  });
  it("rejects duplicate policy names and malformed policies at registration", () => {
    const { auth } = buildModule();
    expect(() => auth.policies.register(definePolicy("a", () => abstain(), "rbac"))).toThrow(ConfigError);
    expect(() => auth.policies.register({} as never)).toThrow(ConfigError);
  });
  it("publishes an audit event for every decision, and a broken bus cannot alter the outcome", async () => {
    const { auth } = buildModule();
    const seen: string[] = []; auth.events.subscribe("AuthorizationDecided", (e) => { seen.push(e.type); });
    auth.events.subscribe("*", () => { throw new Error("sink down"); });
    expect((await auth.engine.decide(ctx({ action: "profile:read" }))).effect).toBe("allow");
    expect(seen).toEqual(["AuthorizationDecided"]);
  });
});

describe("custom logic: rules and composition", () => {
  const post = (authorId: string) => ({ type: "post", id: "1", data: { authorId } });

  it("owner-or-admin, not suspended", async () => {
    const { auth } = buildModule();
    const canEdit = all(any(isOwner("authorId"), hasRole("admin")), not(hasRole("banned")));
    auth.policies.register(allowWhen("post:update", canEdit, "edit-post"));
    const run = (subject: AuthorizationContext["subject"], authorId: string) =>
      auth.engine.decide(ctx({ subject, resource: post(authorId) }));

    expect((await run({ id: "u1", roles: ["user"] }, "u1")).effect).toBe("allow");   // owner
    expect((await run({ id: "u2", roles: ["user"] }, "u1")).effect).toBe("deny");    // stranger
    expect((await run({ id: "u2", roles: ["admin"] }, "u1")).effect).toBe("allow");  // admin
    expect((await run({ id: "u1", roles: ["user", "banned"] }, "u1")).effect).toBe("deny"); // banned owner
  });
  it("denyWhen overrides allows (kill-switch for suspended users)", async () => {
    const { auth } = buildModule();
    auth.policies.register(denyWhen("*", hasRole("banned"), "ban"));
    expect((await auth.engine.decide(ctx({ action: "profile:read", subject: { id: "u", roles: ["admin", "banned"] } }))).effect).toBe("deny");
  });
  it("isOwner is safe against missing/odd resource data", async () => {
    for (const data of [undefined, null, 5, "str", {}, { authorId: 42 }]) {
      expect(await isOwner("authorId").test(ctx({ resource: { type: "post", data } }))).toBe(false);
    }
  });
});

describe("combining algorithms", () => {
  const A = { effect: "allow" } as const, D = { effect: "deny", reason: "no" } as const, X = { effect: "abstain" } as const;
  it("deny-overrides", () => { const c = new DenyOverrides(); expect(c.combine([A, D]).effect).toBe("deny"); expect(c.combine([X]).effect).toBe("deny"); expect(c.combine([A, X]).effect).toBe("allow"); });
  it("allow-overrides", () => { expect(new AllowOverrides().combine([D, A]).effect).toBe("allow"); });
  it("first-applicable", () => { const c = new FirstApplicable(); expect(c.combine([X, D, A]).effect).toBe("deny"); expect(c.combine([X, X]).effect).toBe("deny"); });
});

describe("roles", () => {
  it("detects inheritance cycles and unknown parents at boot", () => {
    expect(() => new InMemoryRoleRegistry().define("a", [], ["b"]).define("b", [], ["a"]).validate()).toThrow(/cycle/);
    expect(() => new InMemoryRoleRegistry().define("a", [], ["ghost"]).validate()).toThrow(/unknown role/);
  });
  it("cyclic data can never hang permission lookup", async () => {
    const r = new InMemoryRoleRegistry().define("a", ["x"], ["b"]).define("b", ["y"], ["a"]);
    expect([...(await r.permissionsFor(["a"]))].sort()).toEqual(["x", "y"]);
  });
  it("unknown roles grant nothing", async () => {
    expect((await new InMemoryRoleRegistry().permissionsFor(["ghost"])).size).toBe(0);
  });
});

describe("resource loaders", () => {
  it("missing loader is a ConfigError; missing resource is a 404-type error", async () => {
    const { auth } = buildModule();
    await expect(auth.resources.load("post", "1")).rejects.toBeInstanceOf(ConfigError);
    auth.resources.register("post", () => null);
    await expect(auth.resources.load("post", "1")).rejects.toBeInstanceOf(ResourceNotFoundError);
  });
});

describe("config validation (fail fast at boot)", () => {
  it("rejects short secrets, bad TTL ordering, unknown default roles", () => {
    expect(() => buildModule({ jwt: { secret: "short" } })).toThrow(/jwt.secret/);
    expect(() => buildModule({ refreshTtlSeconds: 1000, absoluteSessionTtlSeconds: 500 })).toThrow(/absoluteSessionTtlSeconds/);
    expect(() => buildModule({ defaultRoles: ["ghost"] })).toThrow(/ghost/);
  });
  it("refuses in-memory stores in production", () => {
    const prev = process.env.NODE_ENV; process.env.NODE_ENV = "production";
    try { expect(() => buildModule()).toThrow(/production/); } finally { process.env.NODE_ENV = prev; }
  });
});
