/**
 * Generates the install's egress interception CA: an ECDSA P-256 key and a
 * self-signed X.509 v3 CA certificate, in the `{"certPem","keyPem"}` form the
 * egress gateway reads from Secrets Manager (see
 * crates/egress-gateway/src/ca.rs).
 */
import { createHash, generateKeyPairSync, randomBytes, sign, type KeyObject } from "node:crypto";

import {
  bitString,
  boolean,
  explicit,
  implicitPrimitive,
  objectIdentifier,
  octetString,
  sequence,
  set,
  smallInteger,
  time,
  toPem,
  unsignedInteger,
  utf8String,
} from "./der.js";

const OID = {
  ecdsaWithSha256: "1.2.840.10045.4.3.2",
  commonName: "2.5.4.3",
  organizationName: "2.5.4.10",
  subjectKeyIdentifier: "2.5.29.14",
  keyUsage: "2.5.29.15",
  basicConstraints: "2.5.29.19",
  authorityKeyIdentifier: "2.5.29.35",
} as const;

export interface GeneratedCa {
  certPem: string;
  keyPem: string;
  notBefore: Date;
  notAfter: Date;
  serialHex: string;
}

export interface CaOptions {
  commonName: string;
  organization?: string;
  validityYears?: number;
  now?: Date;
}

function name(commonName: string, organization: string): Buffer {
  const rdn = (oid: string, value: string) => set(sequence(objectIdentifier(oid), utf8String(value)));
  return sequence(rdn(OID.organizationName, organization), rdn(OID.commonName, commonName));
}

function extension(oid: string, critical: boolean, value: Buffer): Buffer {
  return critical
    ? sequence(objectIdentifier(oid), boolean(true), octetString(value))
    : sequence(objectIdentifier(oid), octetString(value));
}

/** The BIT STRING payload of a SubjectPublicKeyInfo (the EC point). */
function publicKeyBits(spkiDer: Buffer): Buffer {
  // For P-256 the uncompressed point is the last 65 bytes of the SPKI.
  const point = spkiDer.subarray(spkiDer.length - 65);
  if (point[0] !== 0x04) throw new Error("unexpected P-256 public key encoding");
  return point;
}

export function generateCa(opts: CaOptions): GeneratedCa {
  const now = opts.now ?? new Date();
  const validityYears = opts.validityYears ?? 10;
  const organization = opts.organization ?? "Weft Sandboxes";
  if (opts.commonName.length === 0 || opts.commonName.length > 64) throw new Error("the CA common name must be 1-64 characters");

  const { publicKey, privateKey } = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const spki = publicKey.export({ type: "spki", format: "der" });
  // RFC 5280 method 1: SHA-1 of the subjectPublicKey bits (an identifier, not a security control).
  const keyId = createHash("sha1").update(publicKeyBits(spki)).digest();

  // Backdated an hour for clock skew between the gateway and sandboxes.
  const notBefore = new Date(Math.floor(now.getTime() / 1000) * 1000 - 60 * 60 * 1000);
  const notAfter = new Date(notBefore);
  notAfter.setUTCFullYear(notAfter.getUTCFullYear() + validityYears);

  const serial = randomBytes(16);
  serial[0] = (serial[0]! & 0x7f) | 0x01; // positive and exactly 16 bytes
  const signatureAlgorithm = sequence(objectIdentifier(OID.ecdsaWithSha256));
  const subject = name(opts.commonName, organization);

  const extensions = sequence(
    // CA:TRUE, pathlen 0: the gateway issues leaves directly from this CA.
    extension(OID.basicConstraints, true, sequence(boolean(true), smallInteger(0))),
    // keyCertSign (bit 5) and cRLSign (bit 6): 0b0000011 with one unused bit.
    extension(OID.keyUsage, true, bitString(Buffer.from([0x06]), 1)),
    extension(OID.subjectKeyIdentifier, false, octetString(keyId)),
    extension(OID.authorityKeyIdentifier, false, sequence(implicitPrimitive(0, keyId))),
  );

  const tbs = sequence(
    explicit(0, smallInteger(2)), // v3
    unsignedInteger(serial),
    signatureAlgorithm,
    subject, // issuer (self-signed)
    sequence(time(notBefore), time(notAfter)),
    subject,
    spki,
    explicit(3, extensions),
  );
  const signature = sign("sha256", tbs, privateKey as KeyObject); // DER ECDSA-Sig-Value
  const cert = sequence(tbs, signatureAlgorithm, bitString(signature));

  return {
    certPem: toPem("CERTIFICATE", cert),
    keyPem: privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
    notBefore,
    notAfter,
    serialHex: serial.toString("hex"),
  };
}

/** The CA's common name for a stack, within the 64-character X.520 limit. */
export function caCommonName(stackName: string): string {
  const prefix = "Weft Sandboxes egress CA ";
  return prefix + stackName.slice(0, 64 - prefix.length);
}
