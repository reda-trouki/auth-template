import { PublicUser, toPublicUser, User } from "../domain/entities";
import { EmailAlreadyExistsError } from "../domain/errors";
import { normalizeEmail, PasswordPolicy } from "../domain/validation";
import { IUserRepository } from "../ports/repositories";
import { IClock, ICrypto, IEventBus, IPasswordHasher } from "../ports/services";

export interface RegisterUserInput {
  email: string;
  password: string;
  /**
   * Trusted callers only (seed scripts, admin tools). The HTTP adapter NEVER forwards
   * this field, so clients cannot grant themselves roles (mass-assignment protection).
   */
  roles?: readonly string[];
}

export class RegisterUser {
  constructor(
    private readonly users: IUserRepository,
    private readonly hasher: IPasswordHasher,
    private readonly policy: PasswordPolicy,
    private readonly crypto: ICrypto,
    private readonly clock: IClock,
    private readonly events: IEventBus,
    private readonly defaultRoles: readonly string[],
  ) {}

  async execute(input: RegisterUserInput): Promise<PublicUser> {
    const email = normalizeEmail(input.email);
    this.policy.assertValid(input.password);

    // Fast path only. The repository's unique constraint is the real guarantee (race-safe).
    if (await this.users.findByEmail(email)) throw new EmailAlreadyExistsError();

    const now = this.clock.now();
    const user: User = {
      id: this.crypto.uuid(),
      email,
      passwordHash: await this.hasher.hash(input.password),
      roles: [...(input.roles ?? this.defaultRoles)],
      status: "active",
      failedLoginAttempts: 0,
      lockedUntil: null,
      createdAt: now,
      updatedAt: now,
    };

    await this.users.create(user); // may throw EmailAlreadyExistsError on a lost race
    await this.events.publish({ type: "UserRegistered", userId: user.id, occurredAt: now });
    return toPublicUser(user);
  }
}
