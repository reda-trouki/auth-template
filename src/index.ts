// Public API: host projects import ONLY from here.
export { createAuthModule } from "./config/container";
export type { AuthModule, AuthModuleOptions, RoleDefinition } from "./config/container";

// Errors
export * from "./core/domain/errors";

// Domain types
export type { User, PublicUser, Session, TokenPair, Subject, AuthResult } from "./core/domain/entities";
export type { DomainEvent, DomainEventType } from "./core/domain/events";

// Ports (implement these to plug in your own infrastructure)
export type { IUserRepository, ISessionRepository } from "./core/ports/repositories";
export type {
  IClock, ICrypto, IPasswordHasher, ITokenService, IEventBus, ILogger, EventHandler,
  AccessTokenClaims, VerifiedAccessToken,
} from "./core/ports/services";
export type {
  AuthorizationContext, Decision, IAuthorizationPolicy, ICombiningAlgorithm, IRoleProvider,
} from "./core/ports/IAuthorizationPolicy";

// Authorization toolkit
export { PolicyEngine } from "./authorization/PolicyEngine";
export { PolicyRegistry } from "./authorization/PolicyRegistry";
export { InMemoryRoleRegistry } from "./authorization/RoleRegistry";
export { ResourceLoaderRegistry } from "./authorization/ResourceLoaderRegistry";
export { RbacPolicy } from "./authorization/policies/RbacPolicy";
export { DenyOverrides, AllowOverrides, FirstApplicable } from "./authorization/combining/algorithms";
export {
  allow, deny, abstain, definePolicy, rule, all, any, not,
  hasRole, isOwner, attributeEquals, allowWhen, denyWhen,
} from "./authorization/composition/helpers";
export type { Rule } from "./authorization/composition/helpers";
export { matchesAction } from "./authorization/actions";

// Default adapters (reusable building blocks)
export { InMemoryUserRepository } from "./infrastructure/persistence/in-memory/InMemoryUserRepository";
export { InMemorySessionRepository } from "./infrastructure/persistence/in-memory/InMemorySessionRepository";
export { ScryptPasswordHasher } from "./infrastructure/security/ScryptPasswordHasher";
export { JwtTokenService } from "./infrastructure/security/JwtTokenService";
export { NodeCrypto, SystemClock } from "./infrastructure/security/NodeCrypto";
export { InMemoryEventBus } from "./infrastructure/events/InMemoryEventBus";
export { SafeEventBus } from "./infrastructure/decorators/SafeEventBus";
export { InMemoryRateLimitStore } from "./presentation/http/middleware/rateLimit";
export type { IRateLimitStore } from "./presentation/http/middleware/rateLimit";
export { consoleLogger, noopLogger } from "./infrastructure/logging/loggers";
