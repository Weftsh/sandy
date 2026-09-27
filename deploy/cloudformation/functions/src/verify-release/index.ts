/** Lambda entry point for `Custom::WeftReleaseVerification` and `Custom::WeftNetworkPreflight`. */
import { readFileSync } from "node:fs";
import { join } from "node:path";

import {
  DescribeImagesCommand,
  DescribeInstanceTypesCommand,
  DescribeManagedPrefixListsCommand,
  DescribeSubnetsCommand,
  DescribeVpcAttributeCommand,
  DescribeVpcsCommand,
  EC2Client,
  type _InstanceType,
} from "@aws-sdk/client-ec2";
import { GetFunctionConfigurationCommand, LambdaClient } from "@aws-sdk/client-lambda";
import { GetObjectCommand, S3Client } from "@aws-sdk/client-s3";

import { customResource, withIamPropagationRetry } from "../shared/custom-resource.js";
import { dispatch, type VerifyDeps } from "./handler.js";
import { sigstoreVerifier, type SignatureVerifier } from "./signature.js";

const region = process.env.AWS_REGION ?? "us-east-1";
const s3 = new S3Client({ region });
const ec2 = new EC2Client({ region });
const lambda = new LambdaClient({ region });

let cachedVerifier: SignatureVerifier | undefined;

const deps: VerifyDeps = {
  region,
  async getObject(bucket, key, maxBytes) {
    let res;
    try {
      res = await withIamPropagationRetry(() => s3.send(new GetObjectCommand({ Bucket: bucket, Key: key })));
    } catch (e) {
      throw new Error(`reading s3://${bucket}/${key} failed: ${(e as Error).name}: ${(e as Error).message}`);
    }
    if ((res.ContentLength ?? 0) > maxBytes) throw new Error(`s3://${bucket}/${key} is larger than ${maxBytes} bytes`);
    const bytes = await res.Body!.transformToByteArray();
    if (bytes.length > maxBytes) throw new Error(`s3://${bucket}/${key} is larger than ${maxBytes} bytes`);
    return bytes;
  },
  async describeImage(imageId) {
    try {
      const res = await ec2.send(new DescribeImagesCommand({ ImageIds: [imageId] }));
      const img = res.Images?.[0];
      return img?.ImageId ? { imageId: img.ImageId, state: img.State, architecture: img.Architecture } : undefined;
    } catch (e) {
      // An AMI that exists but is not shared with this account is reported as not found.
      if ((e as Error).name === "InvalidAMIID.NotFound" || (e as Error).name === "InvalidAMIID.Unavailable") return undefined;
      throw e;
    }
  },
  async functionCodeSha256(functionName) {
    const res = await withIamPropagationRetry(() =>
      lambda.send(new GetFunctionConfigurationCommand({ FunctionName: functionName })),
    );
    if (!res.CodeSha256) throw new Error(`Lambda did not report CodeSha256 for ${functionName}`);
    return res.CodeSha256;
  },
  async vpcCidrs(vpcId) {
    const res = await ec2.send(new DescribeVpcsCommand({ VpcIds: [vpcId] }));
    const vpc = res.Vpcs?.[0];
    if (!vpc?.CidrBlock) return [];
    const extra = (vpc.CidrBlockAssociationSet ?? [])
      .filter((a) => a.CidrBlockState?.State === "associated" && a.CidrBlock && a.CidrBlock !== vpc.CidrBlock)
      .map((a) => a.CidrBlock!);
    return [vpc.CidrBlock, ...extra];
  },
  async vpcDns(vpcId) {
    const [support, hostnames] = await Promise.all([
      ec2.send(new DescribeVpcAttributeCommand({ VpcId: vpcId, Attribute: "enableDnsSupport" })),
      ec2.send(new DescribeVpcAttributeCommand({ VpcId: vpcId, Attribute: "enableDnsHostnames" })),
    ]);
    return { support: support.EnableDnsSupport?.Value === true, hostnames: hostnames.EnableDnsHostnames?.Value === true };
  },
  async subnets(subnetIds) {
    if (subnetIds.length === 0) return [];
    const res = await ec2.send(new DescribeSubnetsCommand({ SubnetIds: subnetIds }));
    return (res.Subnets ?? []).map((s) => ({ subnetId: s.SubnetId!, vpcId: s.VpcId, availabilityZone: s.AvailabilityZone }));
  },
  async instanceTypes(types) {
    if (types.length === 0) return [];
    try {
      const res = await ec2.send(new DescribeInstanceTypesCommand({ InstanceTypes: types as _InstanceType[] }));
      return (res.InstanceTypes ?? []).map((t) => ({
        instanceType: t.InstanceType!,
        architectures: t.ProcessorInfo?.SupportedArchitectures ?? [],
        bareMetal: t.BareMetal === true,
        processorFeatures: t.ProcessorInfo?.SupportedFeatures ?? [],
      }));
    } catch (e) {
      if ((e as Error).name === "InvalidInstanceType") throw new Error(`an instance type is not offered in ${region}: ${(e as Error).message}`);
      throw e;
    }
  },
  async s3PrefixListId() {
    const name = `com.amazonaws.${region}.s3`;
    const res = await ec2.send(
      new DescribeManagedPrefixListsCommand({ Filters: [{ Name: "prefix-list-name", Values: [name] }] }),
    );
    const id = res.PrefixLists?.[0]?.PrefixListId;
    if (!id) throw new Error(`the managed prefix list ${name} was not found`);
    return id;
  },
  verifier() {
    // Bundled by the release workflow from Sigstore's TUF repository.
    cachedVerifier ??= sigstoreVerifier(
      JSON.parse(readFileSync(join(process.env.LAMBDA_TASK_ROOT ?? process.cwd(), "trusted-root.json"), "utf8")),
    );
    return cachedVerifier;
  },
};

export const handler = customResource((event) => dispatch(event, deps));
