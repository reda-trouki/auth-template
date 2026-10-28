/**
 * Every failure the library can raise extends AppError.
 * - `code`       stable machine-readable identifier (safe for clients)
 * - `httpStatus` mapping used by the HTTP adapter only
 * - `expose`     false => message is NEVER sent to clients (internal errors)
 */
export abstract class AppError extends Error {
  abstract readonly code: string;
  abstract readonly httpStatus: number;
  readonly expose: boolean = true;

  constructor(message: string, readonly details?: unknown) {
    super(message);
    this.name = new.target.name;
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

export class ValidationError extends AppError {
  readonly code = "VALIDATION_ERROR";
  readonly httpStatus = 400;
  constructor(message = "Invalid request", details?: unknown) { super(message, details); }
}

/** Deliberately identical for "unknown user" and "wrong password" (no user enumeration). */
export class InvalidCredentialsError extends AppError {
  readonly code = "INVALID_CREDENTIALS";
  readonly httpStatus = 401;
  constructor() { super("Invalid email or password"); }
}

export class UnauthenticatedError extends AppError {
  readonly code = "UNAUTHENTICATED";
  readonly httpStatus = 401;
  constructor(message = "Authentication required") { super(message); }
}

export class TokenInvalidError extends AppError {
  readonly code = "TOKEN_INVALID";
  readonly httpStatus = 401;
  constructor(message = "Invalid token") { super(message); }
}

export class TokenExpiredError extends AppError {
  readonly code = "TOKEN_EXPIRED";
  readonly httpStatus = 401;
  constructor(message = "Token expired") { super(message); }
}

export class ForbiddenError extends AppError {
  readonly code = "FORBIDDEN";
  readonly httpStatus = 403;
  constructor(message = "You do not have permission to perform this action") { super(message); }
}

export class AccountSuspendedError extends AppError {
  readonly code = "ACCOUNT_SUSPENDED";
  readonly httpStatus = 403;
  constructor() { super("This account is suspended"); }
}

export class AccountLockedError extends AppError {
  readonly code = "ACCOUNT_LOCKED";
  readonly httpStatus = 423;
  constructor(readonly retryAfterSeconds: number) {
    super("Account temporarily locked due to repeated failed logins");
  }
}

export class TooManyRequestsError extends AppError {
  readonly code = "TOO_MANY_REQUESTS";
  readonly httpStatus = 429;
  constructor(readonly retryAfterSeconds: number) { super("Too many requests"); }
}

export class EmailAlreadyExistsError extends AppError {
  readonly code = "EMAIL_ALREADY_EXISTS";
  readonly httpStatus = 409;
  constructor() { super("An account with this email already exists"); }
}

export class ResourceNotFoundError extends AppError {
  readonly code = "RESOURCE_NOT_FOUND";
  readonly httpStatus = 404;
  constructor(message = "Resource not found") { super(message); }
}

export class PayloadTooLargeError extends AppError {
  readonly code = "PAYLOAD_TOO_LARGE";
  readonly httpStatus = 413;
  constructor() { super("Request body too large"); }
}

/** Programmer / deployment mistakes. Thrown at boot so bad setups never reach production traffic. */
export class ConfigError extends AppError {
  readonly code = "CONFIG_ERROR";
  readonly httpStatus = 500;
  override readonly expose = false;
  constructor(message: string) { super(message); }
}

export class InternalError extends AppError {
  readonly code = "INTERNAL_ERROR";
  readonly httpStatus = 500;
  override readonly expose = false;
  constructor(message = "Internal error", override readonly cause?: unknown) { super(message); }
}
