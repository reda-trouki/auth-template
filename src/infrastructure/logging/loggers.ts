import { ILogger } from "../../core/ports/services";

export const noopLogger: ILogger = { debug() {}, info() {}, warn() {}, error() {} };

export const consoleLogger: ILogger = {
  debug: (m, meta) => console.debug(`[auth] ${m}`, meta ?? ""),
  info: (m, meta) => console.info(`[auth] ${m}`, meta ?? ""),
  warn: (m, meta) => console.warn(`[auth] ${m}`, meta ?? ""),
  error: (m, meta) => console.error(`[auth] ${m}`, meta ?? ""),
};
