import { z } from "zod";
import { ConfigError } from "../core/domain/errors";

const limit = (windowMs: number, max: number) =>
  z.object({ windowMs: z.number().int().positive().default(windowMs), max: z.number().int().positive().default(max) }).default({ windowMs, max });

/** Everything that is plain data is validated here, once, at boot. */
export const ConfigSchema = z
  .object({
    jwt: z.object({
      secret: z.string().min(32, "jwt.secret must be at least 32 characters (use 32+ random bytes)"),
      issuer: z.string().min(1).default("auth-template"),
      audience: z.string().min(1).default("auth-template-clients"),
      accessTtlSeconds: z.number().int().min(30).max(3600).default(900),
    }),
    refreshTtlSeconds: z.number().int().min(60).default(7 * 24 * 3600),
    absoluteSessionTtlSeconds: z.number().int().min(60).default(30 * 24 * 3600),
    strictSessionCheck: z.boolean().default(false),
    defaultRoles: z.array(z.string().min(1)).min(1).default(["user"]),
    password: z.object({ minLength: z.number().int().min(8).default(10), maxLength: z.number().int().max(1024).default(128) }).default({ minLength: 10, maxLength: 128 }),
    lockout: z.object({
      maxAttempts: z.number().int().min(3).default(5),
      durationSeconds: z.number().int().positive().default(900),
    }).default({ maxAttempts: 5, durationSeconds: 900 }),
    rateLimits: z.object({
      login: limit(15 * 60_000, 20),
      register: limit(60 * 60_000, 20),
      refresh: limit(60_000, 60),
    }).default({ login: { windowMs: 900_000, max: 20 }, register: { windowMs: 3_600_000, max: 20 }, refresh: { windowMs: 60_000, max: 60 } }),
    policyTimeoutMs: z.number().int().positive().default(2000),
    bodyLimit: z.string().default("10kb"),
    allowInMemoryInProduction: z.boolean().default(false),
  })
  .refine((c) => c.absoluteSessionTtlSeconds >= c.refreshTtlSeconds, {
    message: "absoluteSessionTtlSeconds must be >= refreshTtlSeconds",
    path: ["absoluteSessionTtlSeconds"],
  })
  .refine((c) => c.password.maxLength >= c.password.minLength, {
    message: "password.maxLength must be >= password.minLength",
    path: ["password", "maxLength"],
  });

export type ResolvedConfig = z.infer<typeof ConfigSchema>;

export function resolveConfig(raw: unknown): ResolvedConfig {
  const parsed = ConfigSchema.safeParse(raw);
  if (!parsed.success) {
    const lines = parsed.error.issues.map((i) => `  - ${i.path.join(".") || "(root)"}: ${i.message}`);
    throw new ConfigError(`Invalid auth configuration:\n${lines.join("\n")}`);
  }
  return parsed.data;
}
