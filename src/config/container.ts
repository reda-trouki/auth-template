import type { ErrorRequestHandler, RequestHandler, Router } from "express";
import { ConfigError } from "../core/domain/errors";
import { PasswordPolicy } from "../core/domain/validation";
import { ICombiningAlgorithm, IRoleProvider } from "../core/ports/IAuthorizationPolicy";
import { ISessionRepository, IUserRepository } from "../core/ports/repositories";
import { IClock, ICrypto, IEventBus, ILogger, IPasswordHasher, ITokenService } from "../core/ports/services";
import { TokenIssuer } from "../core/services/TokenIssuer";
import { AuthenticateToken } from "../core/use-cases/AuthenticateToken";
import { ChangePassword } from "../core/use-cases/ChangePassword";
import { LoginUser } from "../core/use-cases/LoginUser";
import { LogoutUser } from "../core/use-cases/LogoutUser";
import { RefreshSession } from "../core/use-cases/RefreshSession";
import { RegisterUser } from "../core/use-cases/RegisterUser";
import { DenyOverrides } from "../authorization/combining/algorithms";
import { PolicyEngine } from "../authorization/PolicyEngine";
import { PolicyRegistry } from "../authorization/PolicyRegistry";
import { RbacPolicy } from "../authorization/policies/RbacPolicy";
import { ResourceLoaderRegistry } from "../authorization/ResourceLoaderRegistry";
import { InMemoryRoleRegistry } from "../authorization/RoleRegistry";
import { SafeEventBus } from "../infrastructure/decorators/SafeEventBus";
import { InMemoryEventBus } from "../infrastructure/events/InMemoryEventBus";
import { consoleLogger } from "../infrastructure/logging/loggers";
import { InMemorySessionRepository } from "../infrastructure/persistence/in-memory/InMemorySessionRepository";
import { InMemoryUserRepository } from "../infrastructure/persistence/in-memory/InMemoryUserRepository";
import { JwtTokenService } from "../infrastructure/security/JwtTokenService";
import { NodeCrypto, SystemClock } from "../infrastructure/security/NodeCrypto";
import { ScryptPasswordHasher } from "../infrastructure/security/ScryptPasswordHasher";
import { AuthController } from "../presentation/http/controllers/AuthController";
import { createAuthenticate } from "../presentation/http/middleware/authenticate";
import { AuthorizeOptions, createAuthorize } from "../presentation/http/middleware/authorize";
import { createErrorHandler, notFoundHandler } from "../presentation/http/middleware/errorHandler";
import { IRateLimitStore, InMemoryRateLimitStore } from "../presentation/http/middleware/rateLimit";
import { buildRouter } from "../presentation/http/routes";
import { resolveConfig } from "./options";
import "../presentation/http/express-types";

export interface RoleDefinition { permissions: string[]; inherits?: string[] }

/** Data options are validated by ConfigSchema; the optional collaborators below are your swap points. */
export interface AuthModuleOptions {
  jwt: { secret: string; issuer?: string; audience?: string; accessTtlSeconds?: number };
  refreshTtlSeconds?: number;
  absoluteSessionTtlSeconds?: number;
  strictSessionCheck?: boolean;
  defaultRoles?: string[];
  password?: { minLength?: number; maxLength?: number };
  lockout?: { maxAttempts?: number; durationSeconds?: number };
  rateLimits?: Record<string, { windowMs?: number; max?: number }>;
  policyTimeoutMs?: number;
  bodyLimit?: string;
  allowInMemoryInProduction?: boolean;

  /** Role definitions for the built-in RBAC policy. Ignored if `roleProvider` is given. */
  roles?: Record<string, RoleDefinition>;

  // ---- swappable collaborators (Dependency Inversion) ----
  userRepository?: IUserRepository;
  sessionRepository?: ISessionRepository;
  hasher?: IPasswordHasher;
  tokenService?: ITokenService;
  roleProvider?: IRoleProvider;
  combiningAlgorithm?: ICombiningAlgorithm;
  eventBus?: IEventBus;
  rateLimitStore?: IRateLimitStore;
  clock?: IClock;
  crypto?: ICrypto;
  logger?: ILogger;
}

const DEFAULT_ROLES: Record<string, RoleDefinition> = {
  user: { permissions: ["profile:*"] },
  admin: { permissions: ["*"], inherits: ["user"] },
};

/** Composition root: the ONLY place concrete classes are chosen and wired. */
export function createAuthModule(options: AuthModuleOptions) {
  const cfg = resolveConfig(options);
  const logger = options.logger ?? consoleLogger;
  const clock = options.clock ?? new SystemClock();
  const crypto = options.crypto ?? new NodeCrypto();

  const usingMemoryStore = !options.userRepository || !options.sessionRepository;
  if (usingMemoryStore) {
    if (process.env.NODE_ENV === "production" && !cfg.allowInMemoryInProduction) {
      throw new ConfigError("In-memory repositories are not allowed in production. Provide userRepository and sessionRepository.");
    }
    logger.warn("Using in-memory repositories: data is lost on restart and not shared between processes.");
  }
  const users = options.userRepository ?? new InMemoryUserRepository();
  const sessions = options.sessionRepository ?? new InMemorySessionRepository();

  const events: IEventBus = new SafeEventBus(options.eventBus ?? new InMemoryEventBus(logger), logger);
  const hasher = options.hasher ?? new ScryptPasswordHasher();
  const tokens = options.tokenService ?? new JwtTokenService(cfg.jwt, clock);
  const passwordPolicy = new PasswordPolicy(cfg.password.minLength, cfg.password.maxLength);

  // ---- authorization ----
  const roles = new InMemoryRoleRegistry();
  for (const [name, def] of Object.entries(options.roles ?? DEFAULT_ROLES)) roles.define(name, def.permissions, def.inherits ?? []);
  if (!options.roleProvider) {
    roles.validate();
    for (const r of cfg.defaultRoles) {
      if (!roles.has(r)) throw new ConfigError(`defaultRoles contains "${r}" which is not a defined role`);
    }
  }
  const policies = new PolicyRegistry().register(new RbacPolicy(options.roleProvider ?? roles));
  const resources = new ResourceLoaderRegistry();
  const engine = new PolicyEngine(policies, options.combiningAlgorithm ?? new DenyOverrides(), events, clock, logger, {
    policyTimeoutMs: cfg.policyTimeoutMs,
  });

  // ---- use cases ----
  const issuer = new TokenIssuer(sessions, tokens, crypto, clock, {
    refreshTtlSeconds: cfg.refreshTtlSeconds,
    absoluteSessionTtlSeconds: cfg.absoluteSessionTtlSeconds,
  });
  const useCases = {
    registerUser: new RegisterUser(users, hasher, passwordPolicy, crypto, clock, events, cfg.defaultRoles),
    loginUser: new LoginUser(users, hasher, passwordPolicy, issuer, clock, events, cfg.lockout),
    refreshSession: new RefreshSession(sessions, users, issuer, crypto, clock, events),
    logoutUser: new LogoutUser(sessions, crypto, clock, events),
    changePassword: new ChangePassword(users, sessions, hasher, passwordPolicy, clock, events),
    authenticateToken: new AuthenticateToken(tokens, sessions, cfg.strictSessionCheck),
  };

  // ---- http ----
  const errorHandler: ErrorRequestHandler = createErrorHandler(logger);
  const authenticate: RequestHandler = createAuthenticate(useCases.authenticateToken);
  const authorizeFactory = createAuthorize(engine, resources, clock);
  const controller = new AuthController(
    useCases.registerUser, useCases.loginUser, useCases.refreshSession,
    useCases.logoutUser, useCases.changePassword, users,
  );
  const router: Router = buildRouter({
    controller, authenticate, errorHandler,
    rateLimitStore: options.rateLimitStore ?? new InMemoryRateLimitStore(50_000),
    limits: cfg.rateLimits,
    bodyLimit: cfg.bodyLimit,
  });

  return {
    /** Mount at e.g. "/auth". */
    router,
    /** Route guard: verifies the Bearer token, sets req.auth. */
    authenticate: (): RequestHandler => authenticate,
    /** Route guard: runs the policy engine for `action`. Always place after authenticate(). */
    authorize: (action: string, opts?: AuthorizeOptions): RequestHandler => authorizeFactory(action, opts),
    /** Mount LAST on the host app so every error (including 404s) gets a safe JSON response. */
    errorHandler,
    notFoundHandler,
    // extension points
    policies, roles, resources, events, engine, useCases,
  };
}

export type AuthModule = ReturnType<typeof createAuthModule>;
