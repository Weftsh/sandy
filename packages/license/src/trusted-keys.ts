/**
 * Ed25519 public keys trusted to sign Weft licenses, keyed by `kid`.
 *
 * These keys are compiled into every release. The matching private keys live
 * only in AWS KMS in Weft's billing account and never leave it.
 *
 * Adding or rotating a key: create an ECC_NIST_EDWARDS25519 KMS key, export
 * its public key (`aws kms get-public-key`), add it here under a new `kid`,
 * and keep the old entry until every key it signed has expired. The release
 * workflow refuses to publish a tagged release while this map is empty.
 */
export const RELEASE_SIGNING_KEYS: Readonly<Record<string, string>> = Object.freeze({});
