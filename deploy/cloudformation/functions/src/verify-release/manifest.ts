/**
 * The signed release manifest and the checks the stack runs against it.
 *
 * The release workflow writes `release-manifest.json` and signs it keylessly
 * with Sigstore (`cosign sign-blob --bundle`). Everything in this file is pure
 * so the checks can be unit-tested without AWS or Sigstore.
 */

/** Repository and workflow whose GitHub Actions OIDC identity signs releases. */
export const RELEASE_REPOSITORY = "weftsh/byoc";
export const RELEASE_WORKFLOW_PATH = ".github/workflows/release.yml";
export const GITHUB_ACTIONS_ISSUER = "https://token.actions.githubusercontent.com";

const VERSION_RE = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/;
const DIGEST_RE = /^sha256:[0-9a-f]{64}$/;
const SHA256_HEX_RE = /^[0-9a-f]{64}$/;
const AMI_RE = /^ami-[0-9a-f]{8,17}$/;
const REGION_RE = /^[a-z]{2}(?:-[a-z]+)+-\d+$/;

export interface ReleaseManifest {
  schemaVersion: 1;
  product: "weft-sandboxes";
  version: string;
  gitCommit?: string;
  createdAt?: string;
  /** Region to host AMI ID. */
  amis: Record<string, string>;
  /** Component name to image repository and digest. */
  images: Record<string, { repository: string; digest: string }>;
  /** Release-bucket-relative path to SHA-256 (hex) and size. */
  artifacts: Record<string, { sha256: string; size?: number }>;
}

export interface SignerIdentity {
  subjectAlternativeName: string;
  issuer: string;
}

/** The only certificate identity accepted for a release: this repository's release workflow at the release tag. */
export function releaseSignerIdentity(version: string): SignerIdentity {
  assertVersion(version);
  return {
    subjectAlternativeName: `https://github.com/${RELEASE_REPOSITORY}/${RELEASE_WORKFLOW_PATH}@refs/tags/v${version}`,
    issuer: GITHUB_ACTIONS_ISSUER,
  };
}

export function assertVersion(version: string): void {
  if (!VERSION_RE.test(version)) throw new Error(`invalid release version ${JSON.stringify(version)}`);
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

/** Parses and strictly validates the manifest's shape. */
export function parseManifest(bytes: Uint8Array): ReleaseManifest {
  let raw: unknown;
  try {
    raw = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  } catch {
    throw new Error("the release manifest is not valid UTF-8 JSON");
  }
  if (!isRecord(raw)) throw new Error("the release manifest must be a JSON object");
  if (raw.schemaVersion !== 1) throw new Error(`unsupported release manifest schemaVersion ${String(raw.schemaVersion)}`);
  if (raw.product !== "weft-sandboxes") throw new Error("the release manifest is not for weft-sandboxes");
  if (typeof raw.version !== "string") throw new Error("the release manifest has no version");
  assertVersion(raw.version);

  if (!isRecord(raw.amis)) throw new Error("the release manifest has no amis map");
  const amis: Record<string, string> = {};
  for (const [region, ami] of Object.entries(raw.amis)) {
    if (!REGION_RE.test(region) || typeof ami !== "string" || !AMI_RE.test(ami)) {
      throw new Error(`the release manifest has an invalid AMI entry for ${JSON.stringify(region)}`);
    }
    amis[region] = ami;
  }

  if (!isRecord(raw.images)) throw new Error("the release manifest has no images map");
  const images: ReleaseManifest["images"] = {};
  for (const [name, img] of Object.entries(raw.images)) {
    if (!isRecord(img) || typeof img.repository !== "string" || typeof img.digest !== "string" || !DIGEST_RE.test(img.digest)) {
      throw new Error(`the release manifest has an invalid image entry ${JSON.stringify(name)}`);
    }
    images[name] = { repository: img.repository, digest: img.digest };
  }

  if (!isRecord(raw.artifacts)) throw new Error("the release manifest has no artifacts map");
  const artifacts: ReleaseManifest["artifacts"] = {};
  for (const [path, art] of Object.entries(raw.artifacts)) {
    if (!isRecord(art) || typeof art.sha256 !== "string" || !SHA256_HEX_RE.test(art.sha256)) {
      throw new Error(`the release manifest has an invalid artifact entry ${JSON.stringify(path)}`);
    }
    artifacts[path] = { sha256: art.sha256, size: typeof art.size === "number" ? art.size : undefined };
  }

  return {
    schemaVersion: 1,
    product: "weft-sandboxes",
    version: raw.version,
    gitCommit: typeof raw.gitCommit === "string" ? raw.gitCommit : undefined,
    createdAt: typeof raw.createdAt === "string" ? raw.createdAt : undefined,
    amis,
    images,
    artifacts,
  };
}

/** Extracts `sha256:<hex>` from an image reference that must be pinned by digest. */
export function imageDigest(ref: string): string {
  const at = ref.lastIndexOf("@");
  const digest = at > 0 ? ref.slice(at + 1) : "";
  if (!DIGEST_RE.test(digest)) {
    throw new Error(`image ${JSON.stringify(ref)} is not pinned by digest (expected <repository>@sha256:<64 hex>)`);
  }
  return digest;
}

/** Lambda reports CodeSha256 as base64; the manifest records hex. */
export function base64ToHex(b64: string): string {
  return Buffer.from(b64, "base64").toString("hex");
}

export interface ReleaseExpectations {
  /** The version the template was published as. */
  version: string;
  /** Component name to the image reference the stack will run. */
  images: Record<string, string>;
  /** Release artifact path to the deployed Lambda's CodeSha256 (base64). */
  functionCode: Record<string, string>;
}

/**
 * Compares what the stack is about to deploy with the signed manifest.
 * Returns human-readable problems; an empty list means everything matches.
 */
export function checkRelease(manifest: ReleaseManifest, expected: ReleaseExpectations): string[] {
  const problems: string[] = [];
  if (manifest.version !== expected.version) {
    problems.push(`the signed manifest is for version ${manifest.version}, but the template is version ${expected.version}`);
  }
  for (const [component, ref] of Object.entries(expected.images)) {
    let digest: string;
    try {
      digest = imageDigest(ref);
    } catch (e) {
      problems.push((e as Error).message);
      continue;
    }
    const signed = manifest.images[component];
    if (!signed) {
      problems.push(`the signed manifest lists no ${component} image`);
    } else if (signed.digest !== digest) {
      problems.push(`${component} image digest ${digest} is not the signed release digest ${signed.digest}`);
    }
  }
  for (const [artifact, codeSha256] of Object.entries(expected.functionCode)) {
    const signed = manifest.artifacts[artifact];
    if (!signed) {
      problems.push(`the signed manifest lists no ${artifact}`);
      continue;
    }
    const actual = base64ToHex(codeSha256);
    if (actual !== signed.sha256) {
      problems.push(`deployed Lambda code for ${artifact} has SHA-256 ${actual}, but the signed release has ${signed.sha256}`);
    }
  }
  return problems;
}

/** What EC2 reports about the AMI the stack will launch. */
export interface AmiFacts {
  imageId: string;
  state?: string;
  architecture?: string;
}

/**
 * The AMI must be exactly the signed release AMI for this region. Copies are
 * deliberately not accepted: EC2 records the same "source AMI" for a copy and
 * for an image created from a modified instance, so the two cannot be told
 * apart. (Host volumes are encrypted at launch, so no copy is needed for
 * encryption.) Returns problems; empty means accepted.
 */
export function checkAmi(manifest: ReleaseManifest, region: string, ami: AmiFacts | undefined, requested: string): string[] {
  const signedHere = manifest.amis[region];
  if (!signedHere) return [`the signed release has no host AMI for ${region}; deploy in a supported Region`];
  if (requested !== signedHere) return [`AMI ${requested} is not the signed release AMI for ${region} (${signedHere})`];
  if (!ami) {
    return [
      `AMI ${requested} is not available to this account in ${region}. Release AMIs are shared with an account ` +
        `when its Weft license is activated; check that the license is active for this AWS account.`,
    ];
  }
  const problems: string[] = [];
  if (ami.state && ami.state !== "available") problems.push(`AMI ${ami.imageId} is ${ami.state}, not available`);
  if (ami.architecture && ami.architecture !== "x86_64") problems.push(`AMI ${ami.imageId} is ${ami.architecture}; hosts must be x86_64`);
  return problems;
}
