/** Lambda entry point for `Custom::WeftEgressCa`. */
import { PutSecretValueCommand, SecretsManagerClient } from "@aws-sdk/client-secrets-manager";
import { DeleteParameterCommand, GetParameterCommand, PutParameterCommand, SSMClient } from "@aws-sdk/client-ssm";

import { customResource, withIamPropagationRetry } from "../shared/custom-resource.js";
import { generateCa } from "./ca.js";
import { handleEgressCa, type EgressCaDeps } from "./handler.js";

const region = process.env.AWS_REGION ?? "us-east-1";
const secrets = new SecretsManagerClient({ region });
const ssm = new SSMClient({ region });

const deps: EgressCaDeps = {
  async putSecret(secretArn, secretString) {
    await withIamPropagationRetry(() => secrets.send(new PutSecretValueCommand({ SecretId: secretArn, SecretString: secretString })));
  },
  async putParameter(name, value, description) {
    await withIamPropagationRetry(() =>
      ssm.send(
        new PutParameterCommand({ Name: name, Value: value, Type: "String", Tier: "Standard", Overwrite: true, Description: description }),
      ),
    );
  },
  async getParameter(name) {
    try {
      const res = await ssm.send(new GetParameterCommand({ Name: name }));
      return res.Parameter?.Value;
    } catch (e) {
      if ((e as Error).name === "ParameterNotFound") return undefined;
      throw e;
    }
  },
  async deleteParameter(name) {
    try {
      await ssm.send(new DeleteParameterCommand({ Name: name }));
    } catch (e) {
      if ((e as Error).name !== "ParameterNotFound") throw e;
    }
  },
  generate: (commonName) => generateCa({ commonName }),
};

export const handler = customResource((event) => handleEgressCa(event, deps));
