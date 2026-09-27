import type { CloudFormationCustomResourceEvent } from "aws-lambda";
import { describe, expect, it, vi } from "vitest";

import { BUNDLE_NAME, dispatch, MANIFEST_NAME, type VerifyDeps } from "../src/verify-release/handler.js";
import type { SignatureVerifier } from "../src/verify-release/signature.js";
import { D1, D2, sampleManifest, ZIP_B64 } from "./helpers.js";

function event(
  resourceType: string,
  props: Record<string, unknown>,
  requestType: "Create" | "Update" | "Delete" = "Create",
): CloudFormationCustomResourceEvent {
  const base = {
    ServiceToken: "arn:aws:lambda:us-east-1:111122223333:function:verify",
    ResponseURL: "https://example.com/response",
    StackId: "arn:aws:cloudformation:us-east-1:111122223333:stack/weft/1",
    RequestId: "req-1",
    LogicalResourceId: "Res",
    ResourceType: resourceType,
    ResourceProperties: { ServiceToken: "x", ...props },
  };
  if (requestType === "Create") return { ...base, RequestType: "Create" };
  if (requestType === "Update") return { ...base, RequestType: "Update", PhysicalResourceId: "p-1", OldResourceProperties: { ServiceToken: "x" } };
  return { ...base, RequestType: "Delete", PhysicalResourceId: "p-1" };
}

function deps(overrides: Partial<VerifyDeps> = {}, verifier?: SignatureVerifier) {
  const objects: Record<string, Uint8Array> = {
    [`v1.2.3/${MANIFEST_NAME}`]: new TextEncoder().encode(JSON.stringify(sampleManifest())),
    [`v1.2.3/${BUNDLE_NAME}`]: new TextEncoder().encode(JSON.stringify({ mediaType: "bundle" })),
  };
  const verify = vi.fn<SignatureVerifier["verify"]>();
  const d: VerifyDeps = {
    region: "us-east-1",
    getObject: vi.fn(async (_bucket: string, key: string) => {
      const o = objects[key];
      if (!o) throw new Error(`NoSuchKey ${key}`);
      return o;
    }),
    describeImage: vi.fn(async (id: string) => ({ imageId: id, state: "available", architecture: "x86_64" })),
    functionCodeSha256: vi.fn(async () => ZIP_B64),
    vpcCidrs: vi.fn(async () => ["10.0.0.0/16"]),
    vpcDns: vi.fn(async () => ({ support: true, hostnames: true })),
    subnets: vi.fn(async (ids: string[]) =>
      ids.map((id, i) => ({ subnetId: id, vpcId: "vpc-1", availabilityZone: `us-east-1${"abc"[i % 3]}` })),
    ),
    instanceTypes: vi.fn(async (types: string[]) =>
      types.map((t) => ({
        instanceType: t,
        architectures: ["x86_64"],
        bareMetal: t.includes(".metal"),
        processorFeatures: t.includes(".metal") ? [] : ["nested-virtualization"],
      })),
    ),
    s3PrefixListId: vi.fn(async () => "pl-63a5400a"),
    verifier: () => verifier ?? { verify },
    ...overrides,
  };
  return { d, verify };
}

const releaseProps = {
  ReleaseBucket: "weft-releases-us-east-1",
  Version: "1.2.3",
  AmiId: "ami-0123456789abcdef0",
  ControlPlaneImage: `ghcr.io/weftsh/sandbox-control-plane@${D1}`,
  GatewayImage: `ghcr.io/weftsh/sandbox-egress-gateway@${D2}`,
  Functions: [{ Artifact: "functions/egress-ca.zip", Name: "stack-EgressCaFunction-ABC" }],
};

describe("Custom::WeftReleaseVerification", () => {
  it("verifies the signature with the release workflow identity, then checks the manifest", async () => {
    const { d, verify } = deps();
    const res = await dispatch(event("Custom::WeftReleaseVerification", releaseProps), d);
    expect(verify).toHaveBeenCalledOnce();
    const [, payload, identity] = verify.mock.calls[0]!;
    expect(JSON.parse(Buffer.from(payload).toString()).version).toBe("1.2.3");
    expect(identity.subjectAlternativeName).toBe("https://github.com/Weftsh/sandy/.github/workflows/release.yml@refs/tags/v1.2.3");
    expect(d.getObject).toHaveBeenCalledWith("weft-releases-us-east-1", "v1.2.3/release-manifest.json", expect.any(Number));
    expect(d.functionCodeSha256).toHaveBeenCalledWith("stack-EgressCaFunction-ABC");
    expect(res.data?.Version).toBe("1.2.3");
    expect(res.data?.ManifestSha256).toMatch(/^[0-9a-f]{64}$/);
    expect(res.physicalResourceId).toMatch(/^weft-release-1\.2\.3-[0-9a-f]{16}$/);
  });

  it("fails closed when the signature does not verify, without reading the manifest's contents", async () => {
    const parse = vi.spyOn(JSON, "parse");
    const verifier: SignatureVerifier = {
      verify: () => {
        throw new Error("the release manifest signature did not verify: bad");
      },
    };
    const { d } = deps({}, verifier);
    await expect(dispatch(event("Custom::WeftReleaseVerification", releaseProps), d)).rejects.toThrow(/did not verify/);
    // Only the bundle was parsed; the manifest never was.
    expect(parse.mock.calls.every(([s]) => !String(s).includes("weft-sandboxes"))).toBe(true);
    expect(d.describeImage).not.toHaveBeenCalled();
    parse.mockRestore();
  });

  it("refuses unsigned images", async () => {
    const { d } = deps();
    const props = { ...releaseProps, ControlPlaneImage: `evil.example.com/cp@sha256:${"e".repeat(64)}` };
    await expect(dispatch(event("Custom::WeftReleaseVerification", props), d)).rejects.toThrow(
      /control-plane image digest sha256:e{64} is not the signed release digest/,
    );
  });

  it("refuses an AMI that is not the signed one and reports every problem at once", async () => {
    const { d } = deps({ functionCodeSha256: vi.fn(async () => Buffer.alloc(32).toString("base64")) });
    const props = { ...releaseProps, AmiId: "ami-00000000000000000", GatewayImage: "ghcr.io/weftsh/gw:latest" };
    const err = await dispatch(event("Custom::WeftReleaseVerification", props), d).catch((e: Error) => e);
    expect(String(err)).toMatch(/not pinned by digest.*deployed Lambda code.*AMI ami-00000000000000000 is not the signed release AMI/);
  });

  it("fails when the release has not been published for the version", async () => {
    const { d } = deps();
    await expect(dispatch(event("Custom::WeftReleaseVerification", { ...releaseProps, Version: "9.9.9" }), d)).rejects.toThrow(/NoSuchKey/);
  });

  it("re-verifies on update", async () => {
    const { d, verify } = deps();
    await dispatch(event("Custom::WeftReleaseVerification", releaseProps, "Update"), d);
    expect(verify).toHaveBeenCalledOnce();
  });

  it("never blocks deletion", async () => {
    const { d, verify } = deps({ getObject: vi.fn(async () => Promise.reject(new Error("gone"))) });
    const res = await dispatch(event("Custom::WeftReleaseVerification", releaseProps, "Delete"), d);
    expect(res.physicalResourceId).toBe("p-1");
    expect(verify).not.toHaveBeenCalled();
  });
});

const preflightProps = {
  VpcId: "vpc-1",
  PrivateSubnetIds: ["subnet-a", "subnet-b"],
  PublicSubnetIds: [""],
  CheckPublicSubnets: "false",
  SlotPoolCidr: "10.200.0.0/16",
  MaxSandboxesPerHost: "32",
  InstanceTypes: ["c8i.2xlarge", "m8i.2xlarge", ""],
  HostVirtualization: "nested",
};

describe("Custom::WeftNetworkPreflight", () => {
  it("returns the VPC CIDR and S3 prefix list", async () => {
    const { d } = deps();
    const res = await dispatch(event("Custom::WeftNetworkPreflight", preflightProps), d);
    expect(res.data).toEqual({ VpcCidr: "10.0.0.0/16", S3PrefixListId: "pl-63a5400a" });
    expect(d.instanceTypes).toHaveBeenCalledWith(["c8i.2xlarge", "m8i.2xlarge"]);
    expect(d.subnets).toHaveBeenCalledWith(["subnet-a", "subnet-b"]);
  });

  it("rejects a slot pool that overlaps any VPC CIDR", async () => {
    const { d } = deps({ vpcCidrs: vi.fn(async () => ["10.0.0.0/16", "10.200.128.0/20"]) });
    await expect(dispatch(event("Custom::WeftNetworkPreflight", preflightProps), d)).rejects.toThrow(
      /SlotPoolCidr 10.200.0.0\/16 overlaps the VPC CIDR 10.200.128.0\/20/,
    );
  });

  it("rejects instance types without nested virtualization and metal mismatches", async () => {
    const { d } = deps();
    const err = await dispatch(
      event("Custom::WeftNetworkPreflight", { ...preflightProps, InstanceTypes: ["c8i.metal-48xl"] }),
      d,
    ).catch((e: Error) => e);
    expect(String(err)).toMatch(/is bare metal; set HostVirtualization to metal/);

    const { d: d2 } = deps({
      instanceTypes: vi.fn(async () => [
        { instanceType: "c7i.2xlarge", architectures: ["x86_64"], bareMetal: false, processorFeatures: [] },
        { instanceType: "c8g.2xlarge", architectures: ["arm64"], bareMetal: false, processorFeatures: [] },
      ]),
    });
    const err2 = await dispatch(
      event("Custom::WeftNetworkPreflight", { ...preflightProps, InstanceTypes: ["c7i.2xlarge", "c8g.2xlarge"] }),
      d2,
    ).catch((e: Error) => e);
    expect(String(err2)).toMatch(/c7i.2xlarge does not support nested virtualization.*c8g.2xlarge is not x86_64/);
  });

  it("accepts bare metal in metal mode", async () => {
    const { d } = deps();
    const res = await dispatch(
      event("Custom::WeftNetworkPreflight", { ...preflightProps, HostVirtualization: "metal", InstanceTypes: ["c8i.metal-48xl"] }),
      d,
    );
    expect(res.physicalResourceId).toBe("weft-preflight-vpc-1");
  });

  it("checks existing subnets belong to the VPC and span two AZs", async () => {
    const { d } = deps({
      subnets: vi.fn(async () => [
        { subnetId: "subnet-a", vpcId: "vpc-1", availabilityZone: "us-east-1a" },
        { subnetId: "subnet-b", vpcId: "vpc-2", availabilityZone: "us-east-1a" },
      ]),
    });
    const err = await dispatch(event("Custom::WeftNetworkPreflight", preflightProps), d).catch((e: Error) => e);
    expect(String(err)).toMatch(/subnet subnet-b is in vpc-2, not vpc-1.*at least two Availability Zones/);
  });

  it("requires DNS support and hostnames on the VPC", async () => {
    const { d } = deps({ vpcDns: vi.fn(async () => ({ support: true, hostnames: false })) });
    await expect(dispatch(event("Custom::WeftNetworkPreflight", preflightProps), d)).rejects.toThrow(
      /needs enableDnsSupport and enableDnsHostnames/,
    );
  });

  it("rejects unknown resource types", async () => {
    const { d } = deps();
    await expect(dispatch(event("Custom::Other", {}), d)).rejects.toThrow(/unsupported resource type/);
  });
});
