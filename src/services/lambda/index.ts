import { LambdaClient, ListFunctionsCommand } from "@aws-sdk/client-lambda";
import type { ServiceModule, ServiceModuleFactory } from "../../core/types.js";
import { buildLambdaTools } from "./tools.js";

/** AWS Lambda: function inventory, configuration, and error triage. */
const createLambdaModule: ServiceModuleFactory = (factory) => {
  const mod: ServiceModule = {
    name: "lambda",
    description: "AWS Lambda: function inventory, configuration, error/throttle triage with recent error logs.",
    tools: buildLambdaTools(factory),
    healthCheck: async (ctx) => {
      try {
        const { client } = factory.getClient(LambdaClient, ctx.accountId, ctx.region);
        await client.send(new ListFunctionsCommand({ MaxItems: 1 }));
        return { ok: true };
      } catch (err) {
        return { ok: false, detail: String(err) };
      }
    },
  };
  return mod;
};

export default createLambdaModule;
