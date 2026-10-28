# auth-template

Reusable authentication and authorization for Node.js (TypeScript + Express).
Drop it into any project, plug in your own database, and add your own permission rules without touching the core.

- **Authentication:** register, login, refresh-token rotation, logout, change password, account lockout
- **Authorization:** role-based permissions (RBAC) plus custom rules (owner checks, business hours, anything you write)
- **Swappable parts:** database, password hasher, token service, event bus, rate-limit store
- **Safe by default:** deny when unsure, fail fast on bad config, no internal details leaked

---

## 1. Requirements

- Node.js 18.17 or newer
- npm

## 2. Setup

```bash
# 1. Unzip and enter the project
unzip auth-template.zip -d auth-template && cd auth-template

# 2. Install dependencies
npm install

# 3. Create your environment file and generate a secret
cp .env.example .env
openssl rand -base64 48        # paste the output as JWT_SECRET in .env

# 4. Verify everything works (57 tests)
npm test

# 5. Run the example server on http://localhost:3000
JWT_SECRET="$(grep JWT_SECRET .env | cut -d= -f2-)" npm run dev
```

> `JWT_SECRET` must be at least 32 characters. The app refuses to start otherwise.

### Scripts

| Command | What it does |
|---|---|
| `npm run dev` | Runs `examples/server.ts` |
| `npm test` | Runs all tests (unit, HTTP, repository contract) |
| `npm run typecheck` | TypeScript check without building |
| `npm run build` | Compiles to `dist/` |

---

## 3. Try it in 2 minutes

With the example server running:

```bash
# Register
curl -s -X POST localhost:3000/auth/register \
  -H 'Content-Type: application/json' \
  -d '{"email":"me@example.com","password":"a-long-password-123"}'

# Login (copy accessToken and refreshToken from the response)
curl -s -X POST localhost:3000/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"me@example.com","password":"a-long-password-123"}'

# Call a protected route
curl -s localhost:3000/auth/me -H "Authorization: Bearer <accessToken>"

# Admin-only route (a normal user gets 403)
curl -s localhost:3000/admin/stats -H "Authorization: Bearer <accessToken>"

# Get a new token pair (the old refresh token stops working)
curl -s -X POST localhost:3000/auth/refresh \
  -H 'Content-Type: application/json' \
  -d '{"refreshToken":"<refreshToken>"}'
```

The example server seeds `admin@example.com` / `change-me-please-123`. Log in with it to test admin routes, and delete that seed line before real use.

---

## 4. Adding it to your own project

**Option A: copy the source (simplest).**
Copy the `src/` folder into your project (for example as `src/auth/`), then install the three runtime dependencies:

```bash
npm install express jsonwebtoken zod
npm install -D typescript @types/express @types/jsonwebtoken @types/node
```

**Option B: build and pack it as a package.**

```bash
npm run build && npm pack      # creates auth-template-0.1.0.tgz
# in your other project:
npm install ../auth-template/auth-template-0.1.0.tgz
```

Then wire it up (everything is imported from the single entry point):

```ts
import express from "express";
import { createAuthModule } from "./auth";          // or "auth-template"

const auth = createAuthModule({
  jwt: { secret: process.env.JWT_SECRET! },
  userRepository,        // your database adapter (see section 7)
  sessionRepository,     // your database adapter (see section 7)
});

const app = express();
app.set("trust proxy", 1);                 // if behind a proxy/load balancer
app.use("/auth", auth.router);             // all auth endpoints

app.get("/profile", auth.authenticate(), (req, res) => {
  res.json({ userId: req.auth!.subject.id });
});

app.get("/admin/stats", auth.authenticate(), auth.authorize("admin:read"), handler);

app.use(auth.notFoundHandler);
app.use(auth.errorHandler);                // always last
```

Order rule: `authenticate()` first, then `authorize(...)`. Put `errorHandler` last.

Without `userRepository` and `sessionRepository` it uses in-memory storage, fine for development and tests, and **blocked when `NODE_ENV=production`**.

---

## 5. HTTP endpoints

All paths are relative to where you mounted the router (for example `/auth`).

| Method | Path | Auth | Body | Success |
|---|---|---|---|---|
| POST | `/register` | no | `{ email, password }` | 201 `{ user }` |
| POST | `/login` | no | `{ email, password }` | 200 `{ user, tokens }` |
| POST | `/refresh` | no | `{ refreshToken }` | 200 `{ user, tokens }` |
| POST | `/logout` | no | `{ refreshToken }` | 204 |
| POST | `/logout-all` | Bearer | none | 204 |
| POST | `/change-password` | Bearer | `{ currentPassword, newPassword }` | 204 |
| GET | `/me` | Bearer | none | 200 `{ user }` |

`tokens` looks like:

```json
{
  "accessToken": "eyJ...",
  "accessTokenExpiresAt": "2026-10-27T12:15:00.000Z",
  "refreshToken": "<sessionId>.<secret>",
  "refreshTokenExpiresAt": "2026-11-03T12:00:00.000Z"
}
```

Extra fields in a request body (for example `roles`) are rejected with a 400. Clients can never set their own roles.

### Error format

Every error looks the same:

```json
{ "error": { "code": "TOKEN_EXPIRED", "message": "Access token expired" } }
```

| Code | Status | Meaning |
|---|---|---|
| `VALIDATION_ERROR` | 400 | Bad input (details included) |
| `INVALID_CREDENTIALS` | 401 | Wrong email or password (same message for both) |
| `UNAUTHENTICATED` | 401 | No token sent |
| `TOKEN_INVALID` | 401 | Tampered, malformed, revoked or reused token |
| `TOKEN_EXPIRED` | 401 | Access or refresh token expired |
| `FORBIDDEN` | 403 | Logged in but not allowed |
| `ACCOUNT_SUSPENDED` | 403 | Account is suspended |
| `RESOURCE_NOT_FOUND` | 404 | Unknown route or resource |
| `EMAIL_ALREADY_EXISTS` | 409 | Email taken |
| `PAYLOAD_TOO_LARGE` | 413 | Body over the limit |
| `ACCOUNT_LOCKED` | 423 | Too many failed logins (`Retry-After` header set) |
| `TOO_MANY_REQUESTS` | 429 | Rate limit hit (`Retry-After` header set) |
| `INTERNAL_ERROR` | 500 | Generic, details are logged server-side only |

### How a client should use the tokens

1. Log in, store both tokens.
2. Send `Authorization: Bearer <accessToken>` on each request.
3. On a `401` with code `TOKEN_EXPIRED`, call `/refresh` **once**, store the **new** pair, and retry.
4. Always replace the old refresh token with the new one. Each refresh token works exactly once; reusing an old one logs the user out everywhere (this is the theft protection).
5. If `/refresh` fails, send the user to the login page.

```ts
async function api(path: string, init: RequestInit = {}) {
  let res = await fetch(path, withAuth(init));
  if (res.status === 401 && (await res.clone().json()).error?.code === "TOKEN_EXPIRED") {
    const r = await fetch("/auth/refresh", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ refreshToken: tokens.refreshToken }),
    });
    if (!r.ok) return redirectToLogin();
    tokens = (await r.json()).tokens;          // replace BOTH tokens
    res = await fetch(path, withAuth(init));
  }
  return res;
}
```

If several requests can expire at the same moment, share a single in-flight refresh call between them, otherwise the second one is treated as token reuse.

---

## 6. Authorization: adding your own logic

An action is a string like `"post:update"`. A request is allowed only when a policy explicitly allows it. If nothing allows it, it is denied.

### 6.1 Roles and permissions (no code)

```ts
createAuthModule({
  jwt: { secret },
  roles: {
    user:   { permissions: ["profile:*", "post:read", "post:create"] },
    editor: { permissions: ["post:*"], inherits: ["user"] },
    admin:  { permissions: ["*"], inherits: ["editor"] },
  },
  defaultRoles: ["user"],      // role given to every new registration
});
```

Permission patterns: `"*"` (everything), `"post:*"` (any post action), or an exact `"post:update"`.
If you do not pass `roles`, the defaults are `user` (`profile:*`) and `admin` (`*`).

Create your first admin from trusted code (HTTP can never do this):

```ts
await auth.useCases.registerUser.execute({
  email: "admin@yourapp.com", password: "a-strong-password", roles: ["admin"],
});
```

### 6.2 Custom rules

```ts
import { allowWhen, denyWhen, any, all, not, isOwner, hasRole, attributeEquals } from "./auth";

// Only the author or an admin can update a post
auth.policies.register(
  allowWhen("post:update", any(isOwner("authorId"), hasRole("admin")), "post-owner-or-admin"),
);

// Kill switch: banned users are denied everything, even if a role would allow it
auth.policies.register(denyWhen("*", hasRole("banned"), "ban"));
```

| Helper | Meaning |
|---|---|
| `allowWhen(actions, rule)` | Rule true: allow. Otherwise no opinion (other policies may still allow). |
| `denyWhen(actions, rule)` | Rule true: deny, which overrides any allow. Otherwise no opinion. |
| `all(a, b)`, `any(a, b)`, `not(a)` | Combine rules |
| `hasRole(r)`, `isOwner(field)`, `attributeEquals(k, v)` | Ready-made rules |
| `rule(name, (ctx) => boolean)` | Write your own rule |
| `definePolicy(actions, (ctx) => allow() / deny("why") / abstain())` | Full control |

### 6.3 Rules that need the resource (ownership checks)

Tell the library how to load the resource, then name where the id comes from:

```ts
auth.resources.register("post", (id) => postRepo.findById(id));   // return null if missing

app.put("/posts/:id",
  auth.authenticate(),
  auth.authorize("post:update", { resource: { type: "post", idFrom: "params.id" } }),
  handler,
);
```

`idFrom` accepts `"params.id"`, `"query.x"`, `"body.x"` or a function `(req) => string`.
A missing resource returns 404, a denied one returns 403.

### 6.4 A class-based policy

```ts
import { IAuthorizationPolicy, AuthorizationContext, Decision, abstain, deny } from "./auth";

class BusinessHoursPolicy implements IAuthorizationPolicy {
  readonly name = "business-hours";
  appliesTo = (action: string) => action.startsWith("payroll:");
  evaluate({ environment }: AuthorizationContext): Decision {
    const h = (environment?.time ?? new Date()).getHours();
    return h >= 9 && h < 18 ? abstain() : deny("Outside business hours");
  }
}
auth.policies.register(new BusinessHoursPolicy());
```

### 6.5 What the engine guarantees

- A policy that throws, takes longer than `policyTimeoutMs` (2 s), or returns something malformed counts as a **deny**.
- Default combining is `DenyOverrides` (any deny wins, then any allow, else deny). Change it with `combiningAlgorithm: new AllowOverrides()` or `new FirstApplicable()`.
- Policy names must be unique, so a rule cannot be silently replaced.
- Roles from a database: implement `IRoleProvider` and pass `roleProvider`.
- Role changes after startup: call `auth.roles.validate()` to re-check for cycles or unknown parents.

---

## 7. Connecting your database

Implement two interfaces. Everything else is already done.

```ts
interface IUserRepository {
  findById(id: string): Promise<User | null>;
  findByEmail(email: string): Promise<User | null>;     // email is already normalized
  create(user: User): Promise<void>;                    // throw EmailAlreadyExistsError on duplicate
  update(user: User): Promise<void>;
}

interface ISessionRepository {
  create(session: Session): Promise<void>;
  findById(id: string): Promise<Session | null>;
  consume(id: string, at: Date): Promise<boolean>;      // ATOMIC, see below
  revokeFamily(familyId: string, at: Date): Promise<void>;
  revokeAllForUser(userId: string, at: Date): Promise<void>;
  purgeExpired(before: Date): Promise<number>;
}
```

**Two rules you must follow:**

1. **Unique email in the database.** Put a unique index on `email` and translate the duplicate-key error into `EmailAlreadyExistsError`. This is what makes two simultaneous signups safe.
2. **`consume` must be atomic.** It returns `true` for exactly one caller:

```sql
UPDATE sessions SET used_at = $2
WHERE id = $1 AND used_at IS NULL AND revoked_at IS NULL;
-- return (rowCount === 1)
```

Suggested SQL tables (adapt the types to your database):

```sql
CREATE TABLE users (
  id UUID PRIMARY KEY,
  email TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  roles TEXT[] NOT NULL,
  status TEXT NOT NULL,
  failed_login_attempts INT NOT NULL DEFAULT 0,
  locked_until TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE sessions (
  id UUID PRIMARY KEY,
  user_id UUID NOT NULL REFERENCES users(id),
  family_id UUID NOT NULL,
  secret_hash TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  family_expires_at TIMESTAMPTZ NOT NULL,
  used_at TIMESTAMPTZ,
  revoked_at TIMESTAMPTZ
);
CREATE INDEX sessions_family_idx ON sessions(family_id);
CREATE INDEX sessions_user_idx ON sessions(user_id);
```

**Test your adapter** with the shared contract suite. Copy the pattern from `tests/contract/inMemory.contract.test.ts`:

```ts
import { runUserRepositoryContract, runSessionRepositoryContract } from "./repositories.contract";
runUserRepositoryContract("postgres", () => new PgUserRepository(testPool));
runSessionRepositoryContract("postgres", () => new PgSessionRepository(testPool));
```

Run `purgeExpired(new Date())` from a daily cron or timer to clean old sessions.

### Other swappable parts

| Option | Default | Replace it to... |
|---|---|---|
| `hasher` | scrypt (built in) | use Argon2 or bcrypt (`IPasswordHasher`: `hash`, `verify`) |
| `tokenService` | HS256 JWT | use RS256, PASETO, etc. (`ITokenService`) |
| `eventBus` | in-memory | forward events to Kafka, Redis, a queue (`IEventBus`) |
| `rateLimitStore` | in-memory | use Redis when you run several instances (`IRateLimitStore`) |
| `roleProvider` | in-memory roles | load roles from your DB (`IRoleProvider`) |
| `logger` | console | use pino, winston, etc. (`ILogger`) |

---

## 8. Reacting to security events

```ts
auth.events.subscribe("RefreshTokenReuseDetected", (e) => alertSecurityTeam(e));
auth.events.subscribe("AccountLocked", (e) => emailUser(e.userId));
auth.events.subscribe("*", (e) => auditLog.write(e));       // everything
```

Events: `UserRegistered`, `LoginSucceeded`, `LoginFailed`, `AccountLocked`, `RefreshTokenReuseDetected`, `PasswordChanged`, `LoggedOut`, `AuthorizationDecided` (every allow/deny, including the reason).

A subscriber that throws never breaks a request.

---

## 9. Configuration reference

Only `jwt.secret` is required. Everything is validated at startup.

| Option | Default | Notes |
|---|---|---|
| `jwt.secret` | required | 32+ characters |
| `jwt.issuer` / `jwt.audience` | `auth-template` / `auth-template-clients` | Checked on every token |
| `jwt.accessTtlSeconds` | `900` (15 min) | Allowed range 30 to 3600 |
| `refreshTtlSeconds` | `604800` (7 days) | Renewed on each rotation |
| `absoluteSessionTtlSeconds` | `2592000` (30 days) | Hard cap, must be >= refresh TTL |
| `strictSessionCheck` | `false` | `true` = logout is instant, costs one session lookup per request |
| `defaultRoles` | `["user"]` | Must exist in `roles` |
| `password.minLength` / `maxLength` | `10` / `128` | Max also protects against CPU abuse |
| `lockout.maxAttempts` / `durationSeconds` | `5` / `900` | Per account |
| `rateLimits.login` | 20 per 15 min per IP | Also `register` (20/hour) and `refresh` (60/min) |
| `policyTimeoutMs` | `2000` | Per policy |
| `bodyLimit` | `"10kb"` | Request body cap |
| `allowInMemoryInProduction` | `false` | Leave off |

---

## 10. Project layout

```
src/
  core/               Pure business logic, no framework imports
    domain/           Entities, errors, events, validation
    ports/            Interfaces (repositories, services, policies)
    services/         TokenIssuer
    use-cases/        Register, Login, Refresh, Logout, ChangePassword, AuthenticateToken
  authorization/      PolicyEngine, registries, RBAC, rule helpers, combining algorithms
  infrastructure/     Default adapters: scrypt, JWT, in-memory stores, event bus
  presentation/http/  Express router, controller, middleware, validation schemas
  config/             Config validation and the composition root (createAuthModule)
  index.ts            The only file host projects import from
tests/                unit, integration (HTTP), contract (repository interface)
examples/server.ts    Full working integration
```

Dependency rule: arrows point inward. `core` knows nothing about Express, databases or JWT libraries.

---

## 11. Production checklist

- [ ] Real `userRepository` and `sessionRepository` (in-memory is blocked in production)
- [ ] `JWT_SECRET` from a secret manager, 32+ random characters, never committed
- [ ] HTTPS everywhere, and `app.set("trust proxy", ...)` set correctly (otherwise rate limiting sees only your proxy's IP)
- [ ] `helmet` and a CORS policy configured on the host app
- [ ] Redis-backed `IRateLimitStore` if you run more than one instance
- [ ] A cron job calling `sessions.purgeExpired(new Date())`
- [ ] A subscriber on `RefreshTokenReuseDetected` that alerts someone
- [ ] Remove the example admin seed from `examples/server.ts`
- [ ] Decide on `strictSessionCheck` (instant logout) versus stateless access tokens

---

## 12. Troubleshooting

| Problem | Cause and fix |
|---|---|
| `Invalid auth configuration: jwt.secret ...` on startup | Secret shorter than 32 characters |
| `In-memory repositories are not allowed in production` | Pass real repositories, or set `NODE_ENV=development` locally |
| `defaultRoles contains "x" which is not a defined role` | Add that role to `roles` |
| Always `403` for a valid user | No policy allows that action. Check the role's permissions and the action string. The `AuthorizationDecided` event shows the reason. |
| `500` with `No resource loader registered` | Call `auth.resources.register(type, loader)` before using `authorize` with a `resource` |
| User suddenly logged out everywhere | A used refresh token was presented again (two tabs refreshing at once, or a stale token). Share one refresh call across requests. |
| `429` on login during testing | Per-IP limit; raise `rateLimits.login.max` in development |
| Role change not visible yet | Roles live in the access token and update on next refresh (up to 15 min), or use `strictSessionCheck` and re-login |

---

## 13. Not included yet

Email verification, password reset, MFA, OAuth login, and ready-made Prisma/Mongo adapters. Each fits behind the existing interfaces without changing the core.