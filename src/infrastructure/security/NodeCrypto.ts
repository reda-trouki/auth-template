import { createHash, randomBytes, randomUUID, timingSafeEqual } from "node:crypto";
import { ICrypto } from "../../core/ports/services";

export class NodeCrypto implements ICrypto {
  randomToken(bytes = 32): string { return randomBytes(bytes).toString("base64url"); }
  uuid(): string { return randomUUID(); }
  sha256Hex(input: string): string { return createHash("sha256").update(input).digest("hex"); }
  safeEqual(a: string, b: string): boolean {
    const ba = Buffer.from(a);
    const bb = Buffer.from(b);
    return ba.length === bb.length && timingSafeEqual(ba, bb);
  }
}

export class SystemClock {
  now(): Date { return new Date(); }
}
