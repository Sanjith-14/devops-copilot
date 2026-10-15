import { STSClient, GetCallerIdentityCommand } from "@aws-sdk/client-sts";
import type { ServiceModule, ServiceModuleFactory } from "../../core/types.js";
import { buildSecurityTools } from "./tools.js";

/** Cross-service security posture scorecard (exposed as security_scorecard). */
const createSecurityModule: ServiceModuleFactory = (factory) => {
  const mod: ServiceModule = {
    name: "security",
    description:
      "Cross-service security posture: one scorecard over IAM, S3, security groups, RDS and Secrets Manager with ranked findings (read-only).",
    tools: buildSecurityTools(factory),
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

export default createSecurityModule;
