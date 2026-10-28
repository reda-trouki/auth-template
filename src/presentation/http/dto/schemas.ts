import { z } from "zod";

/** .strict() rejects unknown keys, so `{ "roles": ["admin"] }` on register is a 400, not silently ignored. */
export const registerSchema = z.object({ email: z.string().max(254), password: z.string().max(128) }).strict();
export const loginSchema = registerSchema;
export const refreshSchema = z.object({ refreshToken: z.string().min(1).max(512) }).strict();
export const changePasswordSchema = z
  .object({ currentPassword: z.string().max(128), newPassword: z.string().max(128) })
  .strict();
