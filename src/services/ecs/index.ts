import { ECSClient, ListClustersCommand } from "@aws-sdk/client-ecs";
import type { ServiceModule, ServiceModuleFactory } from "../../core/types.js";
import { buildEcsTools } from "./tools.js";

/** Amazon ECS: clusters and service health with stopped-task diagnostics. */
const createEcsModule: ServiceModuleFactory = (factory) => {
  const mod: ServiceModule = {
    name: "ecs",
    description:
      "Amazon ECS (read-only): clusters, service health (desired vs running, rollouts) and why tasks stopped.",
    tools: buildEcsTools(factory),
    healthCheck: async (ctx) => {
      try {
        const { client } = factory.getClient(ECSClient, ctx.accountId, ctx.region);
        await client.send(new ListClustersCommand({ maxResults: 1 }));
        return { ok: true };
      } catch (err) {
        return { ok: false, detail: String(err) };
      }
    },
  };
  return mod;
};

export default createEcsModule;
