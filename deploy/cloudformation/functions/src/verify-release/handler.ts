/**
 * Two custom resources the stack creates before any compute:
 *
 * - `Custom::WeftReleaseVerification` refuses to proceed unless the release
 *   manifest carries a valid Sigstore signature from this repository's
 *   release workflow at the release tag, and the AMI, container image digests
 *   and Lambda code the stack is about to use are the ones it lists.
 * - `Custom::WeftNetworkPreflight` checks the VPC, subnets, host slot pool
 *   and instance types, and looks up values CloudFormation cannot (the VPC
 *   CIDR of an existing VPC and the S3 managed prefix list).
 *
 * Deletes are always no-ops so a stack can be removed even if the release
 * bucket is gone.
 */
import { createHash } from "node:crypto";

import type { Event, ResourceResult } from "../shared/custom-resource.js";
import { optionalString, requireString, stringList } from "../shared/custom-resource.js";
import type { AmiFacts, ReleaseExpectations } from "./manifest.js";
import { checkAmi, checkRelease, parseManifest, releaseSignerIdentity } from "./manifest.js";
import type { InstanceTypeFacts, SubnetFacts } from "./network.js";
import { checkInstanceTypes, checkSlotPool, checkSubnets } from "./network.js";
import type { SignatureVerifier } from "./signature.js";

export const MANIFEST_NAME = "release-manifest.json";
export const BUNDLE_NAME = "release-manifest.json.sigstore.json";
const MAX_OBJECT_BYTES = 1024 * 1024;

export interface VerifyDeps {
  region: string;
  getObject(bucket: string, key: string, maxBytes: number): Promise<Uint8Array>;
  describeImage(imageId: string): Promise<AmiFacts | undefined>;
  /** Base64 SHA-256 of the function's deployment package. */
  functionCodeSha256(functionName: string): Promise<string>;
  /** Associated IPv4 CIDR blocks, primary first. */
  vpcCidrs(vpcId: string): Promise<string[]>;
  /** The VPC's enableDnsSupport and enableDnsHostnames attributes. */
  vpcDns(vpcId: string): Promise<{ support: boolean; hostnames: boolean }>;
  subnets(subnetIds: string[]): Promise<SubnetFacts[]>;
  instanceTypes(types: string[]): Promise<InstanceTypeFacts[]>;
  s3PrefixListId(): Promise<string>;
  verifier(): SignatureVerifier;
}

function fail(problems: string[]): never {
  throw new Error(problems.join("; "));
}

export async function verifyRelease(event: Event, deps: VerifyDeps): Promise<ResourceResult> {
  const p = event.ResourceProperties as Record<string, unknown>;
  const bucket = requireString(p, "ReleaseBucket");
  const version = requireString(p, "Version");
  const amiId = requireString(p, "AmiId");
  const identity = releaseSignerIdentity(version);
  const prefix = `v${version}/`;

  const [manifestBytes, bundleBytes] = await Promise.all([
    deps.getObject(bucket, prefix + MANIFEST_NAME, MAX_OBJECT_BYTES),
    deps.getObject(bucket, prefix + BUNDLE_NAME, MAX_OBJECT_BYTES),
  ]);
  let bundle: unknown;
  try {
    bundle = JSON.parse(Buffer.from(bundleBytes).toString("utf8"));
  } catch {
    throw new Error(`s3://${bucket}/${prefix}${BUNDLE_NAME} is not JSON`);
  }
  // Signature first: nothing in an unverified manifest is looked at.
  deps.verifier().verify(bundle, Buffer.from(manifestBytes), identity);
  const manifest = parseManifest(manifestBytes);

  const functions = (Array.isArray(p.Functions) ? p.Functions : []) as { Artifact?: unknown; Name?: unknown }[];
  const functionCode: Record<string, string> = {};
  for (const f of functions) {
    if (typeof f.Artifact !== "string" || typeof f.Name !== "string") throw new Error("Functions entries need Artifact and Name");
    functionCode[f.Artifact] = await deps.functionCodeSha256(f.Name);
  }
  const expected: ReleaseExpectations = {
    version,
    images: {
      "control-plane": requireString(p, "ControlPlaneImage"),
      "egress-gateway": requireString(p, "GatewayImage"),
    },
    functionCode,
  };
  const problems = checkRelease(manifest, expected);
  problems.push(...checkAmi(manifest, deps.region, await deps.describeImage(amiId), amiId));
  if (problems.length > 0) fail(problems);

  const manifestSha256 = createHash("sha256").update(manifestBytes).digest("hex");
  console.log(JSON.stringify({ msg: "release verified", version, manifestSha256, signer: identity.subjectAlternativeName }));
  return {
    physicalResourceId: `weft-release-${version}-${manifestSha256.slice(0, 16)}`,
    data: { Version: version, ManifestSha256: manifestSha256, GitCommit: manifest.gitCommit ?? "" },
  };
}

export async function networkPreflight(event: Event, deps: VerifyDeps): Promise<ResourceResult> {
  const p = event.ResourceProperties as Record<string, unknown>;
  const vpcId = requireString(p, "VpcId");
  const privateSubnets = stringList(p, "PrivateSubnetIds");
  const publicSubnets = stringList(p, "PublicSubnetIds");
  const slotPool = requireString(p, "SlotPoolCidr");
  const maxSandboxes = Number(requireString(p, "MaxSandboxesPerHost"));
  const instanceTypes = stringList(p, "InstanceTypes");
  const mode = requireString(p, "HostVirtualization");
  if (mode !== "nested" && mode !== "metal") throw new Error("HostVirtualization must be nested or metal");
  const checkPublic = optionalString(p, "CheckPublicSubnets") === "true";

  const [cidrs, dns, subnets, types, prefixList] = await Promise.all([
    deps.vpcCidrs(vpcId),
    deps.vpcDns(vpcId),
    deps.subnets([...privateSubnets, ...(checkPublic ? publicSubnets : [])]),
    deps.instanceTypes(instanceTypes),
    deps.s3PrefixListId(),
  ]);
  if (cidrs.length === 0) fail([`VPC ${vpcId} was not found or has no IPv4 CIDR`]);
  const problems = [
    // Private hosted zones and Cloud Map resolve only in VPCs with both on.
    ...(dns.support && dns.hostnames ? [] : [`VPC ${vpcId} needs enableDnsSupport and enableDnsHostnames turned on`]),
    ...checkSubnets("PrivateSubnetIds", privateSubnets, subnets, vpcId),
    ...(checkPublic ? checkSubnets("PublicSubnetIds", publicSubnets, subnets, vpcId) : []),
    ...checkSlotPool(slotPool, cidrs, maxSandboxes),
    ...checkInstanceTypes(instanceTypes, types, mode),
  ];
  if (problems.length > 0) fail(problems);
  return {
    physicalResourceId: `weft-preflight-${vpcId}`,
    data: { VpcCidr: cidrs[0]!, S3PrefixListId: prefixList },
  };
}

export async function dispatch(event: Event, deps: VerifyDeps): Promise<ResourceResult> {
  if (event.RequestType === "Delete") {
    return { physicalResourceId: event.PhysicalResourceId };
  }
  switch (event.ResourceType) {
    case "Custom::WeftReleaseVerification":
      return verifyRelease(event, deps);
    case "Custom::WeftNetworkPreflight":
      return networkPreflight(event, deps);
    default:
      throw new Error(`unsupported resource type ${event.ResourceType}`);
  }
}
