/**
 * `Custom::WeftEgressCa`: creates the egress interception CA once per stack.
 *
 * - Create: generates the CA, writes `{"certPem","keyPem"}` as the current
 *   version of the stack's CA secret (whose resource policy lets only the
 *   gateway task role read it) and the public certificate to an SSM
 *   parameter, and returns the certificate as `CertPem`.
 * - Update: keeps the CA; returns the certificate from the SSM parameter.
 *   The CA is regenerated only if the secret itself was replaced.
 * - Delete: removes the SSM parameter. CloudFormation deletes the secret.
 *
 * This function can write the secret but never read it.
 */
import type { Event, ResourceResult } from "../shared/custom-resource.js";
import { requireString } from "../shared/custom-resource.js";
import { caCommonName, generateCa, type GeneratedCa } from "./ca.js";

/** Fixed, so CloudFormation never sends a replacement Delete for the same parameter. */
export const PHYSICAL_ID = "weft-egress-ca";

export interface EgressCaDeps {
  putSecret(secretArn: string, secretString: string): Promise<void>;
  putParameter(name: string, value: string, description: string): Promise<void>;
  /** Returns undefined when the parameter does not exist. */
  getParameter(name: string): Promise<string | undefined>;
  deleteParameter(name: string): Promise<void>;
  generate(commonName: string): GeneratedCa;
}

async function create(props: Record<string, unknown>, deps: EgressCaDeps): Promise<ResourceResult> {
  const secretArn = requireString(props, "SecretArn");
  const parameterName = requireString(props, "CertParameterName");
  const stackName = requireString(props, "StackName");
  const ca = deps.generate(caCommonName(stackName));
  await deps.putSecret(secretArn, JSON.stringify({ certPem: ca.certPem, keyPem: ca.keyPem }));
  await deps.putParameter(
    parameterName,
    ca.certPem,
    `Weft Sandboxes egress CA certificate (public) for stack ${stackName}; serial ${ca.serialHex}`,
  );
  console.log(
    JSON.stringify({ msg: "egress CA created", serial: ca.serialHex, notAfter: ca.notAfter.toISOString(), parameterName }),
  );
  return { physicalResourceId: PHYSICAL_ID, data: { CertPem: ca.certPem, CertParameterName: parameterName } };
}

export async function handleEgressCa(event: Event, deps: EgressCaDeps): Promise<ResourceResult> {
  const props = event.ResourceProperties as Record<string, unknown>;
  switch (event.RequestType) {
    case "Create":
      return create(props, deps);
    case "Update": {
      const old = event.OldResourceProperties as Record<string, unknown>;
      const parameterName = requireString(props, "CertParameterName");
      const oldParameterName = typeof old.CertParameterName === "string" ? old.CertParameterName : parameterName;
      const secretReplaced = old.SecretArn !== props.SecretArn;
      const existing = secretReplaced ? undefined : await deps.getParameter(oldParameterName);
      let result: ResourceResult;
      if (existing === undefined) {
        console.warn(
          JSON.stringify({
            msg: secretReplaced ? "CA secret replaced; generating a new CA" : "CA certificate parameter missing; generating a new CA",
          }),
        );
        result = await create(props, deps);
      } else {
        if (oldParameterName !== parameterName) {
          await deps.putParameter(parameterName, existing, "Weft Sandboxes egress CA certificate (public)");
        }
        result = { physicalResourceId: PHYSICAL_ID, data: { CertPem: existing, CertParameterName: parameterName } };
      }
      if (oldParameterName !== parameterName) await deps.deleteParameter(oldParameterName);
      return result;
    }
    case "Delete": {
      const parameterName = props.CertParameterName;
      if (typeof parameterName === "string" && parameterName !== "") await deps.deleteParameter(parameterName);
      return { physicalResourceId: event.PhysicalResourceId };
    }
  }
}
