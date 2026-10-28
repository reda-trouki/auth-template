import { randomBytes, scrypt, timingSafeEqual, ScryptOptions } from "node:crypto";
import { IPasswordHasher } from "../../core/ports/services";

export interface ScryptParams { N: number; r: number; p: number; keyLength: number }
const DEFAULTS: ScryptParams = { N: 32768, r: 8, p: 1, keyLength: 64 };

const derive = (plain: string, salt: Buffer, p: ScryptParams): Promise<Buffer> =>
  new Promise((resolve, reject) => {
    const opts: ScryptOptions = { N: p.N, r: p.r, p: p.p, maxmem: 256 * p.N * p.r };
    scrypt(plain, salt, p.keyLength, opts, (err, key) => (err ? reject(err) : resolve(key)));
  });

/**
 * Zero-dependency default. Stored format embeds its own parameters:
 *   scrypt$N$r$p$saltB64$hashB64
 * so cost can be raised later without breaking old hashes.
 * Want Argon2? Implement IPasswordHasher around the `argon2` package and inject it.
 */
export class ScryptPasswordHasher implements IPasswordHasher {
  private readonly params: ScryptParams;
  constructor(params: Partial<ScryptParams> = {}) {
    this.params = { ...DEFAULTS, ...params };
    if (this.params.N < 1024 || (this.params.N & (this.params.N - 1)) !== 0) {
      throw new Error("scrypt N must be a power of two >= 1024");
    }
  }

  async hash(plain: string): Promise<string> {
    const salt = randomBytes(16);
    const key = await derive(plain, salt, this.params);
    const { N, r, p } = this.params;
    return `scrypt$${N}$${r}$${p}$${salt.toString("base64")}$${key.toString("base64")}`;
  }

  async verify(plain: string, stored: string): Promise<boolean> {
    try {
      const parts = stored.split("$");
      if (parts.length !== 6 || parts[0] !== "scrypt") return false;
      const [, n, r, p, saltB64, hashB64] = parts as [string, string, string, string, string, string];
      const expected = Buffer.from(hashB64, "base64");
      const params: ScryptParams = { N: Number(n), r: Number(r), p: Number(p), keyLength: expected.length };
      // Refuse absurd parameters from a corrupted/malicious row (memory DoS guard).
      if (!Number.isInteger(params.N) || params.N > 2 ** 20 || params.r > 32 || params.p > 16 || expected.length === 0) return false;
      const actual = await derive(plain, Buffer.from(saltB64, "base64"), params);
      return actual.length === expected.length && timingSafeEqual(actual, expected);
    } catch {
      return false; // contract: never throw
    }
  }
}
