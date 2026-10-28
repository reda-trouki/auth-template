import { AuthResult, toPublicUser, User } from "../domain/entities";
import { AccountLockedError, AccountSuspendedError, InvalidCredentialsError } from "../domain/errors";
import { addSeconds, normalizeEmail, PasswordPolicy, secondsBetween } from "../domain/validation";
import { IUserRepository } from "../ports/repositories";
import { IClock, IEventBus, IPasswordHasher } from "../ports/services";
import { TokenIssuer } from "../services/TokenIssuer";

export interface LoginInput { email: string; password: string; ip?: string; userAgent?: string }
export interface LockoutConfig { maxAttempts: number; durationSeconds: number }

export class LoginUser {
  private dummyHash?: Promise<string>;

  constructor(
    private readonly users: IUserRepository,
    private readonly hasher: IPasswordHasher,
    private readonly policy: PasswordPolicy,
    private readonly issuer: TokenIssuer,
    private readonly clock: IClock,
    private readonly events: IEventBus,
    private readonly lockout: LockoutConfig,
  ) {}

  async execute(input: LoginInput): Promise<AuthResult> {
    const meta = { ip: input.ip, userAgent: input.userAgent };
    const now = this.clock.now();

    // Oversized password: reject BEFORE hashing (CPU DoS guard). Same error as any other failure.
    if (!this.policy.isWithinBounds(input.password)) {
      await this.events.publish({ type: "LoginFailed", reason: "bad_password", occurredAt: now, ...meta });
      throw new InvalidCredentialsError();
    }

    let email: string | null = null;
    try { email = normalizeEmail(input.email); } catch { /* treated as unknown user */ }
    const user = email ? await this.users.findByEmail(email) : null;

    if (!user) {
      await this.burnTime(input.password); // equalize timing with the real-user path
      await this.events.publish({ type: "LoginFailed", reason: "unknown_user", occurredAt: now, ...meta });
      throw new InvalidCredentialsError();
    }

    if (user.lockedUntil && user.lockedUntil > now) {
      await this.events.publish({ type: "LoginFailed", userId: user.id, reason: "locked", occurredAt: now, ...meta });
      throw new AccountLockedError(secondsBetween(now, user.lockedUntil));
    }

    const ok = await this.hasher.verify(input.password, user.passwordHash);
    if (!ok) {
      await this.recordFailure(user, now, meta);
      throw new InvalidCredentialsError();
    }

    // Status is checked AFTER the password so suspended-ness is not leaked to guessers.
    if (user.status !== "active") {
      await this.events.publish({ type: "LoginFailed", userId: user.id, reason: "suspended", occurredAt: now, ...meta });
      throw new AccountSuspendedError();
    }

    let current: User = user;
    if (user.failedLoginAttempts > 0 || user.lockedUntil) {
      current = { ...user, failedLoginAttempts: 0, lockedUntil: null, updatedAt: now };
      await this.users.update(current);
    }

    const tokens = await this.issuer.issue(current);
    await this.events.publish({ type: "LoginSucceeded", userId: current.id, occurredAt: now, ...meta });
    return { user: toPublicUser(current), tokens };
  }

  private async recordFailure(user: User, now: Date, meta: { ip?: string; userAgent?: string }): Promise<void> {
    const attempts = user.failedLoginAttempts + 1;
    let updated: User;
    if (attempts >= this.lockout.maxAttempts) {
      const until = addSeconds(now, this.lockout.durationSeconds);
      updated = { ...user, failedLoginAttempts: 0, lockedUntil: until, updatedAt: now };
      await this.users.update(updated);
      await this.events.publish({ type: "AccountLocked", userId: user.id, until, occurredAt: now });
    } else {
      updated = { ...user, failedLoginAttempts: attempts, lockedUntil: null, updatedAt: now };
      await this.users.update(updated);
    }
    await this.events.publish({ type: "LoginFailed", userId: user.id, reason: "bad_password", occurredAt: now, ...meta });
  }

  private async burnTime(password: string): Promise<void> {
    this.dummyHash ??= this.hasher.hash("timing-equalization-placeholder");
    await this.hasher.verify(password, await this.dummyHash);
  }
}
