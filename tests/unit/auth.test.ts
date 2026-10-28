import { describe, expect, it } from "vitest";
import {
  AccountLockedError, AccountSuspendedError, DomainEvent, EmailAlreadyExistsError, InvalidCredentialsError,
  TokenExpiredError, TokenInvalidError, ValidationError, InMemoryUserRepository,
} from "../../src";
import { buildModule, CREDS } from "../fakes/helpers";

async function registered(over = {}) {
  const ctx = buildModule(over);
  await ctx.auth.useCases.registerUser.execute(CREDS);
  return ctx;
}
const events = (auth: ReturnType<typeof buildModule>["auth"]) => {
  const seen: DomainEvent[] = []; auth.events.subscribe("*", (e) => { seen.push(e); }); return seen;
};

describe("RegisterUser", () => {
  it("normalizes email, never returns the hash, applies default role", async () => {
    const { auth } = buildModule();
    const u = await auth.useCases.registerUser.execute(CREDS);
    expect(u.email).toBe("alice@example.com");
    expect(u.roles).toEqual(["user"]);
    expect(JSON.stringify(u)).not.toContain("scrypt");
  });
  it("rejects duplicates case-insensitively", async () => {
    const { auth } = await registered();
    await expect(auth.useCases.registerUser.execute({ ...CREDS, email: "ALICE@example.com" })).rejects.toBeInstanceOf(EmailAlreadyExistsError);
  });
  it("rejects weak/oversized passwords and bad emails", async () => {
    const { auth } = buildModule();
    await expect(auth.useCases.registerUser.execute({ email: "a@b.co", password: "short" })).rejects.toBeInstanceOf(ValidationError);
    await expect(auth.useCases.registerUser.execute({ email: "a@b.co", password: "x".repeat(500) })).rejects.toBeInstanceOf(ValidationError);
    await expect(auth.useCases.registerUser.execute({ email: "not-an-email", password: "long-enough-pw" })).rejects.toBeInstanceOf(ValidationError);
  });
  it("loses a registration race safely (repository uniqueness is the guarantee)", async () => {
    const { auth } = buildModule();
    const r = await Promise.allSettled([auth.useCases.registerUser.execute(CREDS), auth.useCases.registerUser.execute(CREDS)]);
    expect(r.filter((x) => x.status === "fulfilled")).toHaveLength(1);
  });
});

describe("LoginUser", () => {
  it("logs in and issues tokens", async () => {
    const { auth } = await registered();
    const res = await auth.useCases.loginUser.execute(CREDS);
    expect(res.tokens.accessToken).toBeTruthy();
    expect(res.tokens.refreshToken).toContain(".");
  });
  it("gives the SAME error for unknown user, wrong password and garbage input", async () => {
    const { auth } = await registered();
    for (const input of [
      { email: "ghost@example.com", password: "whatever-password" },
      { email: CREDS.email, password: "wrong-password-here" },
      { email: "garbage", password: "x" },
      { email: CREDS.email, password: "x".repeat(10_000) },
    ]) {
      await expect(auth.useCases.loginUser.execute(input)).rejects.toBeInstanceOf(InvalidCredentialsError);
    }
  });
  it("locks after N failures, then recovers after the lock expires", async () => {
    const { auth, clock } = await registered({ lockout: { maxAttempts: 3, durationSeconds: 60 } });
    for (let i = 0; i < 3; i++) await expect(auth.useCases.loginUser.execute({ ...CREDS, password: "wrong-wrong-wrong" })).rejects.toBeInstanceOf(InvalidCredentialsError);
    await expect(auth.useCases.loginUser.execute(CREDS)).rejects.toBeInstanceOf(AccountLockedError); // even with the right password
    clock.advance(61);
    await expect(auth.useCases.loginUser.execute(CREDS)).resolves.toBeTruthy();
  });
  it("a success resets the failure counter", async () => {
    const { auth } = await registered({ lockout: { maxAttempts: 3, durationSeconds: 60 } });
    for (let i = 0; i < 2; i++) await auth.useCases.loginUser.execute({ ...CREDS, password: "wrong-wrong-wrong" }).catch(() => {});
    await auth.useCases.loginUser.execute(CREDS);
    for (let i = 0; i < 2; i++) await auth.useCases.loginUser.execute({ ...CREDS, password: "wrong-wrong-wrong" }).catch(() => {});
    await expect(auth.useCases.loginUser.execute(CREDS)).resolves.toBeTruthy(); // 2 < 3, not locked
  });
  it("suspended users cannot log in (and only after proving the password)", async () => {
    const users = new InMemoryUserRepository();
    const { auth } = await registered({ userRepository: users, sessionRepository: undefined });
    const u = (await users.findByEmail("alice@example.com"))!;
    await users.update({ ...u, status: "suspended" });
    await expect(auth.useCases.loginUser.execute(CREDS)).rejects.toBeInstanceOf(AccountSuspendedError);
    await expect(auth.useCases.loginUser.execute({ ...CREDS, password: "wrong-wrong-wrong" })).rejects.toBeInstanceOf(InvalidCredentialsError);
  });
  it("a throwing event subscriber never breaks login", async () => {
    const { auth } = await registered();
    auth.events.subscribe("*", () => { throw new Error("audit sink down"); });
    await expect(auth.useCases.loginUser.execute(CREDS)).resolves.toBeTruthy();
  });
});

describe("RefreshSession (rotation + theft detection)", () => {
  it("rotates: new token works, old token is single-use", async () => {
    const { auth } = await registered();
    const first = (await auth.useCases.loginUser.execute(CREDS)).tokens;
    const second = (await auth.useCases.refreshSession.execute({ refreshToken: first.refreshToken })).tokens;
    expect(second.refreshToken).not.toBe(first.refreshToken);
    await expect(auth.useCases.refreshSession.execute({ refreshToken: first.refreshToken })).rejects.toBeInstanceOf(TokenInvalidError);
  });
  it("reuse of an old token revokes the WHOLE family and emits an alert event", async () => {
    const { auth } = await registered();
    const seen = events(auth);
    const first = (await auth.useCases.loginUser.execute(CREDS)).tokens;
    const second = (await auth.useCases.refreshSession.execute({ refreshToken: first.refreshToken })).tokens;
    await auth.useCases.refreshSession.execute({ refreshToken: first.refreshToken }).catch(() => {}); // attacker replays
    await expect(auth.useCases.refreshSession.execute({ refreshToken: second.refreshToken })).rejects.toBeInstanceOf(TokenInvalidError); // victim's token is dead too
    expect(seen.some((e) => e.type === "RefreshTokenReuseDetected")).toBe(true);
  });
  it("concurrent refreshes with the same token: exactly one wins", async () => {
    const { auth } = await registered();
    const t = (await auth.useCases.loginUser.execute(CREDS)).tokens;
    const r = await Promise.allSettled(Array.from({ length: 5 }, () => auth.useCases.refreshSession.execute({ refreshToken: t.refreshToken })));
    expect(r.filter((x) => x.status === "fulfilled")).toHaveLength(1);
  });
  it("rejects malformed, tampered and unknown tokens identically", async () => {
    const { auth } = await registered();
    const t = (await auth.useCases.loginUser.execute(CREDS)).tokens;
    for (const bad of ["", ".", "abc", "a.b", t.refreshToken + "x", t.refreshToken.split(".")[0] + ".wrong", 123 as unknown as string, "x".repeat(5000)]) {
      await expect(auth.useCases.refreshSession.execute({ refreshToken: bad })).rejects.toBeInstanceOf(TokenInvalidError);
    }
  });
  it("expires, and rotation cannot extend past the absolute session cap", async () => {
    const { auth, clock } = await registered({ refreshTtlSeconds: 100, absoluteSessionTtlSeconds: 250 });
    let t = (await auth.useCases.loginUser.execute(CREDS)).tokens;
    for (let i = 0; i < 2; i++) { clock.advance(90); t = (await auth.useCases.refreshSession.execute({ refreshToken: t.refreshToken })).tokens; }
    clock.advance(90); // 270s total > 250s cap
    await expect(auth.useCases.refreshSession.execute({ refreshToken: t.refreshToken })).rejects.toBeInstanceOf(TokenExpiredError);
  });
  it("logout kills the family; logging out twice or with junk is harmless", async () => {
    const { auth } = await registered();
    const t = (await auth.useCases.loginUser.execute(CREDS)).tokens;
    await auth.useCases.logoutUser.execute({ refreshToken: t.refreshToken });
    await auth.useCases.logoutUser.execute({ refreshToken: t.refreshToken });
    await auth.useCases.logoutUser.execute({ refreshToken: "junk" });
    await expect(auth.useCases.refreshSession.execute({ refreshToken: t.refreshToken })).rejects.toBeInstanceOf(TokenInvalidError);
  });
  it("a password change revokes all sessions", async () => {
    const { auth } = await registered();
    const login = await auth.useCases.loginUser.execute(CREDS);
    await auth.useCases.changePassword.execute({ userId: login.user.id, currentPassword: CREDS.password, newPassword: "brand-new-password-1" });
    await expect(auth.useCases.refreshSession.execute({ refreshToken: login.tokens.refreshToken })).rejects.toBeInstanceOf(TokenInvalidError);
    await expect(auth.useCases.loginUser.execute({ ...CREDS, password: "brand-new-password-1" })).resolves.toBeTruthy();
  });
});

describe("Access tokens", () => {
  it("expire on schedule and reject tampering", async () => {
    const { auth, clock } = await registered({ jwt: { secret: "test-secret-test-secret-test-secret-123456", accessTtlSeconds: 60 } });
    const t = (await auth.useCases.loginUser.execute(CREDS)).tokens;
    await expect(auth.useCases.authenticateToken.execute({ accessToken: t.accessToken })).resolves.toBeTruthy();
    await expect(auth.useCases.authenticateToken.execute({ accessToken: t.accessToken.slice(0, -2) + "xx" })).rejects.toBeInstanceOf(TokenInvalidError);
    clock.advance(61);
    await expect(auth.useCases.authenticateToken.execute({ accessToken: t.accessToken })).rejects.toBeInstanceOf(TokenExpiredError);
  });
  it("rejects an unsigned 'alg: none' token", async () => {
    const { auth } = await registered();
    const b64 = (o: object) => Buffer.from(JSON.stringify(o)).toString("base64url");
    const forged = `${b64({ alg: "none", typ: "JWT" })}.${b64({ sub: "x", sid: "y", roles: ["admin"], iat: 1, exp: 9e9, iss: "auth-template", aud: "auth-template-clients" })}.`;
    await expect(auth.useCases.authenticateToken.execute({ accessToken: forged })).rejects.toBeInstanceOf(TokenInvalidError);
  });
  it("strictSessionCheck makes logout immediate", async () => {
    const { auth } = await registered({ strictSessionCheck: true });
    const t = (await auth.useCases.loginUser.execute(CREDS)).tokens;
    await auth.useCases.logoutUser.execute({ refreshToken: t.refreshToken });
    await expect(auth.useCases.authenticateToken.execute({ accessToken: t.accessToken })).rejects.toBeInstanceOf(TokenInvalidError);
  });
});
