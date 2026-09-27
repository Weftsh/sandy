/**
 * License issuance. Used by Weft's billing automation and by tests; the
 * customer stack only verifies.
 */
import { generateKeyPairSync, sign, type KeyObject } from "node:crypto";
import { SignCommand, type KMSClient } from "@aws-sdk/client-kms";

import { encodeLicenseKey, encodePayload, validatePayload, type LicensePayload } from "./key.js";

export interface Signer {
  sign(message: Uint8Array): Promise<Uint8Array>;
}

/** Signs with a local Ed25519 private key. For development and tests. */
export function localSigner(privateKey: KeyObject): Signer {
  if (privateKey.asymmetricKeyType !== "ed25519") {
    throw new Error("license signing key must be Ed25519");
  }
  return { sign: async (message) => sign(null, message, privateKey) };
}

/**
 * Signs with an AWS KMS key of spec ECC_NIST_EDWARDS25519. KMS's
 * ED25519_SHA_512 algorithm over a RAW message is pure Ed25519 (RFC 8032), so
 * the result verifies with any standard Ed25519 implementation.
 */
export function kmsSigner(client: Pick<KMSClient, "send">, keyId: string): Signer {
  return {
    async sign(message) {
      const out = await client.send(
        new SignCommand({
          KeyId: keyId,
          Message: message,
          MessageType: "RAW",
          SigningAlgorithm: "ED25519_SHA_512",
        }),
      );
      if (!out.Signature) throw new Error("KMS returned no signature");
      return out.Signature;
    },
  };
}

export async function issueLicenseKey(payload: LicensePayload, signer: Signer): Promise<string> {
  const problem = validatePayload(payload);
  if (problem) throw new Error(`invalid license payload: ${problem}`);
  const payloadPart = encodePayload(payload);
  const signature = await signer.sign(Buffer.from(payloadPart, "utf8"));
  return encodeLicenseKey(payloadPart, signature);
}

/** Generates an Ed25519 key pair as PEM strings. */
export function generateSigningKeyPair(): { publicKeyPem: string; privateKeyPem: string } {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  return {
    publicKeyPem: publicKey.export({ type: "spki", format: "pem" }).toString(),
    privateKeyPem: privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
  };
}
