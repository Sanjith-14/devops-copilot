import { ResourceGroupsTaggingAPIClient, GetResourcesCommand } from "@aws-sdk/client-resource-groups-tagging-api";
import type { ServiceModule, ServiceModuleFactory } from "../../core/types.js";
import { buildTaggingTools } from "./tools.js";

/** Resource Groups Tagging API: cross-service inventory and tag compliance. */
const createTaggingModule: ServiceModuleFactory = (factory) => {
  const mod: ServiceModule = {
    name: "tagging",
    description:
      "Cross-service resource inventory and tag compliance via the Resource Groups Tagging API (read-only).",
    tools: buildTaggingTools(factory),
    healthCheck: async (ctx) => {
      try {
        const { client } = factory.getClient(ResourceGroupsTaggingAPIClient, ctx.accountId, ctx.region);
        await client.send(new GetResourcesCommand({ ResourcesPerPage: 1 }));
        return { ok: true };
      } catch (err) {
        return { ok: false, detail: String(err) };
      }
    },
  };
  return mod;
};

export default createTaggingModule;
