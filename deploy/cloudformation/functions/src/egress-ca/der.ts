/**
 * The handful of DER (X.690) encoders needed to build one X.509 certificate.
 * Kept deliberately small so it can be reviewed in full; the tests parse the
 * output with Node's X509Certificate and, when available, OpenSSL.
 */

function encodeLength(n: number): Buffer {
  if (n < 0x80) return Buffer.from([n]);
  const bytes: number[] = [];
  for (let v = n; v > 0; v = Math.floor(v / 256)) bytes.unshift(v & 0xff);
  return Buffer.from([0x80 | bytes.length, ...bytes]);
}

export function tlv(tag: number, content: Buffer): Buffer {
  return Buffer.concat([Buffer.from([tag]), encodeLength(content.length), content]);
}

export const sequence = (...items: Buffer[]): Buffer => tlv(0x30, Buffer.concat(items));
export const set = (...items: Buffer[]): Buffer => tlv(0x31, Buffer.concat(items));
export const octetString = (b: Buffer): Buffer => tlv(0x04, b);
export const utf8String = (s: string): Buffer => tlv(0x0c, Buffer.from(s, "utf8"));
export const boolean = (v: boolean): Buffer => tlv(0x01, Buffer.from([v ? 0xff : 0x00]));
/** `[n] EXPLICIT` context-specific constructed tag. */
export const explicit = (n: number, inner: Buffer): Buffer => tlv(0xa0 | n, inner);
/** `[n] IMPLICIT` context-specific primitive tag. */
export const implicitPrimitive = (n: number, content: Buffer): Buffer => tlv(0x80 | n, content);

/** A non-negative INTEGER from big-endian magnitude bytes. */
export function unsignedInteger(magnitude: Buffer): Buffer {
  let i = 0;
  while (i < magnitude.length - 1 && magnitude[i] === 0) i++;
  let b = magnitude.subarray(i);
  if (b.length === 0) b = Buffer.from([0]);
  if (b[0]! & 0x80) b = Buffer.concat([Buffer.from([0]), b]);
  return tlv(0x02, b);
}

export const smallInteger = (n: number): Buffer => {
  if (!Number.isInteger(n) || n < 0 || n > 0xffff) throw new Error("smallInteger out of range");
  return unsignedInteger(Buffer.from([n >> 8, n & 0xff]));
};

export function bitString(bytes: Buffer, unusedBits = 0): Buffer {
  if (unusedBits < 0 || unusedBits > 7) throw new Error("unusedBits out of range");
  return tlv(0x03, Buffer.concat([Buffer.from([unusedBits]), bytes]));
}

export function objectIdentifier(oid: string): Buffer {
  const arcs = oid.split(".").map((a) => {
    const n = Number(a);
    if (!Number.isSafeInteger(n) || n < 0) throw new Error(`invalid OID ${oid}`);
    return n;
  });
  if (arcs.length < 2 || arcs[0]! > 2) throw new Error(`invalid OID ${oid}`);
  const out: number[] = [];
  const push = (v: number) => {
    const chunk = [v & 0x7f];
    for (let x = Math.floor(v / 128); x > 0; x = Math.floor(x / 128)) chunk.unshift((x & 0x7f) | 0x80);
    out.push(...chunk);
  };
  push(arcs[0]! * 40 + arcs[1]!);
  for (const a of arcs.slice(2)) push(a);
  return tlv(0x06, Buffer.from(out));
}

const pad = (n: number, width = 2) => String(n).padStart(width, "0");

/** RFC 5280 section 4.1.2.5: UTCTime through 2049, GeneralizedTime from 2050. */
export function time(d: Date): Buffer {
  const y = d.getUTCFullYear();
  const rest = `${pad(d.getUTCMonth() + 1)}${pad(d.getUTCDate())}${pad(d.getUTCHours())}${pad(d.getUTCMinutes())}${pad(d.getUTCSeconds())}Z`;
  if (y >= 1950 && y < 2050) return tlv(0x17, Buffer.from(`${pad(y % 100)}${rest}`, "ascii"));
  return tlv(0x18, Buffer.from(`${pad(y, 4)}${rest}`, "ascii"));
}

export function toPem(label: string, der: Buffer): string {
  const b64 = der.toString("base64").match(/.{1,64}/g) ?? [];
  return `-----BEGIN ${label}-----\n${b64.join("\n")}\n-----END ${label}-----\n`;
}
