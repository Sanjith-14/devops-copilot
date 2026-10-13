import { STSClient, GetCallerIdentityCommand } from "@aws-sdk/client-sts";
import type { ServiceModule, ServiceModuleFactory } from "../../core/types.js";
import { buildAwsTools } from "./tools.js";

/** Generic read-only access to any AWS API (exposed as `aws_read`). */
const createAwsModule: ServiceModuleFactory = (factory) => {
  const mod: ServiceModule = {
    name: "aws",
    description:
      "Generic read-only AWS API access (aws_read) for services without dedicated tools. Allowlisted to Describe/List/Get operations.",
    tools: buildAwsTools(factory),
    healthCheck: async (ctx) => {
      try {
        const { client } = factory.getClient(STSClient, ctx.accountId, ctx.region);
        await client.send(new GetCallerIdentityCommand({}));
        return { ok: true };
      } catch (err) {
        return { ok: false, detail: String(err) };
      }
    },
  };
  return mod;
};

export default createAwsModule;
