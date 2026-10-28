import { describe, expect, it } from "vitest";
import { IUserRepository, ISessionRepository, User, Session, EmailAlreadyExistsError } from "../../src";

const user = (over: Partial<User> = {}): User => ({
  id: "u1", email: "a@b.co", passwordHash: "h", roles: ["user"], status: "active",
  failedLoginAttempts: 0, lockedUntil: null, createdAt: new Date(0), updatedAt: new Date(0), ...over,
});
const session = (over: Partial<Session> = {}): Session => ({
  id: "s1", userId: "u1", familyId: "f1", secretHash: "x", createdAt: new Date(0),
  expiresAt: new Date(1e12), familyExpiresAt: new Date(1e12), usedAt: null, revokedAt: null, ...over,
});

/** Liskov check: every adapter must pass this suite, so they are interchangeable. */
export function runUserRepositoryContract(name: string, make: () => IUserRepository) {
  describe(`IUserRepository contract: ${name}`, () => {
    it("creates and finds by id and email", async () => {
      const r = make(); await r.create(user());
      expect((await r.findById("u1"))?.email).toBe("a@b.co");
      expect((await r.findByEmail("a@b.co"))?.id).toBe("u1");
      expect(await r.findById("nope")).toBeNull();
    });
    it("rejects duplicate emails (even concurrently)", async () => {
      const r = make();
      const results = await Promise.allSettled([r.create(user({ id: "1" })), r.create(user({ id: "2" }))]);
      expect(results.filter((x) => x.status === "fulfilled")).toHaveLength(1);
      const rejected = results.find((x) => x.status === "rejected") as PromiseRejectedResult;
      expect(rejected.reason).toBeInstanceOf(EmailAlreadyExistsError);
    });
    it("returns copies, not live references", async () => {
      const r = make(); await r.create(user());
      const a = await r.findById("u1");
      (a!.roles as string[]).push("admin");
      expect((await r.findById("u1"))!.roles).toEqual(["user"]);
    });
    it("updates", async () => {
      const r = make(); await r.create(user());
      await r.update(user({ failedLoginAttempts: 3 }));
      expect((await r.findById("u1"))!.failedLoginAttempts).toBe(3);
    });
  });
}

export function runSessionRepositoryContract(name: string, make: () => ISessionRepository) {
  describe(`ISessionRepository contract: ${name}`, () => {
    it("consume() succeeds exactly once under a race", async () => {
      const r = make(); await r.create(session());
      const results = await Promise.all(Array.from({ length: 10 }, () => r.consume("s1", new Date())));
      expect(results.filter(Boolean)).toHaveLength(1);
    });
    it("cannot consume a revoked or unknown session", async () => {
      const r = make(); await r.create(session()); await r.revokeFamily("f1", new Date());
      expect(await r.consume("s1", new Date())).toBe(false);
      expect(await r.consume("ghost", new Date())).toBe(false);
    });
    it("revokeFamily is idempotent and scoped to the family", async () => {
      const r = make();
      await r.create(session()); await r.create(session({ id: "s2", familyId: "f2" }));
      await r.revokeFamily("f1", new Date()); await r.revokeFamily("f1", new Date());
      expect((await r.findById("s1"))!.revokedAt).not.toBeNull();
      expect((await r.findById("s2"))!.revokedAt).toBeNull();
    });
    it("revokeAllForUser revokes every family of that user", async () => {
      const r = make();
      await r.create(session()); await r.create(session({ id: "s2", familyId: "f2" }));
      await r.revokeAllForUser("u1", new Date());
      expect((await r.findById("s2"))!.revokedAt).not.toBeNull();
    });
  });
}
