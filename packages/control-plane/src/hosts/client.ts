/**
 * Client for one host agent.
 *
 * Every connection verifies the host's self-signed certificate against the
 * exact certificate the host registered through its IAM-authenticated
 * heartbeat (pinning), and presents the host's bearer token.
 */
import https from "node:https";
import tls from "node:tls";
import { X509Certificate } from "node:crypto";
import type { Duplex } from "node:stream";

import type { Host } from "../store/types.js";

export class HostError extends Error {
  constructor(
    readonly status: number,
    message: string,
  ) {
    super(message);
    this.name = "HostError";
  }
}

const SERVER_NAME = "weft-host-agent";

export class HostClient {
  readonly fingerprint: string;
  private agent: https.Agent;

  constructor(readonly host: Host) {
    this.fingerprint = new X509Certificate(host.certPem).fingerprint256;
    this.agent = new https.Agent({ keepAlive: true, maxSockets: 64, ...this.tlsOptions() });
  }

  private tlsOptions(): tls.ConnectionOptions {
    const expected = this.fingerprint;
    return {
      ca: [this.host.certPem],
      servername: SERVER_NAME,
      minVersion: "TLSv1.2",
      checkServerIdentity: (_name, cert) =>
        cert.fingerprint256 === expected ? undefined : new Error("host certificate does not match its registration"),
    };
  }

  close(): void {
    this.agent.destroy();
  }

  async request<T>(method: string, path: string, body?: unknown, timeoutMs = 120_000): Promise<T> {
    const payload = body === undefined ? undefined : Buffer.from(JSON.stringify(body));
    return new Promise<T>((resolve, reject) => {
      const req = https.request(
        {
          host: this.host.privateIp,
          port: this.host.apiPort,
          method,
          path,
          agent: this.agent,
          headers: {
            authorization: `Bearer ${this.host.token}`,
            ...(payload ? { "content-type": "application/json", "content-length": payload.length } : {}),
          },
          timeout: timeoutMs,
        },
        (res) => {
          const chunks: Buffer[] = [];
          res.on("data", (c: Buffer) => chunks.push(c));
          res.on("end", () => {
            const text = Buffer.concat(chunks).toString("utf8");
            const status = res.statusCode ?? 500;
            if (status >= 200 && status < 300) {
              resolve((text ? JSON.parse(text) : undefined) as T);
              return;
            }
            let message = text;
            try {
              message = (JSON.parse(text) as { message?: string }).message ?? text;
            } catch {
              // not JSON
            }
            reject(new HostError(status, message || `host returned HTTP ${status}`));
          });
          res.on("error", reject);
        },
      );
      req.on("timeout", () => req.destroy(new HostError(504, `host ${this.host.hostId} timed out`)));
      req.on("error", (e) => reject(e instanceof HostError ? e : new HostError(502, `host ${this.host.hostId} unreachable: ${e.message}`)));
      req.end(payload);
    });
  }

  /** Opens a raw TCP tunnel to a port on a sandbox running on this host. */
  openTunnel(sandboxId: string, port: number, timeoutMs = 10_000): Promise<Duplex> {
    return new Promise((resolve, reject) => {
      const socket = tls.connect({ host: this.host.privateIp, port: this.host.tunnelPort, ...this.tlsOptions() });
      const timer = setTimeout(() => {
        socket.destroy();
        reject(new HostError(504, "tunnel handshake timed out"));
      }, timeoutMs);
      let buf = Buffer.alloc(0);
      const fail = (e: Error) => {
        clearTimeout(timer);
        socket.destroy();
        reject(e instanceof HostError ? e : new HostError(502, e.message));
      };
      socket.once("error", fail);
      socket.once("secureConnect", () => {
        socket.write(
          `CONNECT ${sandboxId}:${port} HTTP/1.1\r\nHost: ${sandboxId}:${port}\r\nAuthorization: Bearer ${this.host.token}\r\n\r\n`,
        );
      });
      const onData = (chunk: Buffer) => {
        buf = Buffer.concat([buf, chunk]);
        const end = buf.indexOf("\r\n\r\n");
        if (end < 0) {
          if (buf.length > 16_384) fail(new HostError(502, "tunnel response too large"));
          return;
        }
        socket.off("data", onData);
        clearTimeout(timer);
        const head = buf.subarray(0, end).toString("latin1");
        const status = Number(/^HTTP\/1\.[01] (\d{3})/.exec(head)?.[1] ?? 502);
        const rest = buf.subarray(end + 4);
        if (status !== 200) {
          let message = rest.toString("utf8");
          try {
            message = (JSON.parse(message) as { message?: string }).message ?? message;
          } catch {
            // not JSON
          }
          socket.destroy();
          reject(new HostError(status, message || `tunnel refused with HTTP ${status}`));
          return;
        }
        socket.off("error", fail);
        if (rest.length > 0) socket.unshift(rest);
        resolve(socket);
      };
      socket.on("data", onData);
    });
  }
}
