import type { Subject } from "../../core/domain/entities";

export interface AuthContext { subject: Subject; sessionId: string }

declare global {
  // eslint-disable-next-line @typescript-eslint/no-namespace
  namespace Express {
    interface Request { auth?: AuthContext }
  }
}
export {};
