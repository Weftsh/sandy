/** Structured JSON logs on stdout (CloudWatch Logs in production). */
export interface Logger {
  info(msg: string, fields?: Record<string, unknown>): void;
  warn(msg: string, fields?: Record<string, unknown>): void;
  error(msg: string, fields?: Record<string, unknown>): void;
}

export function jsonLogger(component: string, write: (line: string) => void = (l) => process.stdout.write(l)): Logger {
  const emit = (level: string, msg: string, fields?: Record<string, unknown>) =>
    write(`${JSON.stringify({ time: new Date().toISOString(), level, component, msg, ...fields })}\n`);
  return {
    info: (m, f) => emit("info", m, f),
    warn: (m, f) => emit("warn", m, f),
    error: (m, f) => emit("error", m, f),
  };
}

export const silentLogger: Logger = { info() {}, warn() {}, error() {} };
