import { CloudTrailClient, LookupEventsCommand } from "@aws-sdk/client-cloudtrail";
import type { ServiceModule, ServiceModuleFactory } from "../../core/types.js";
import { buildCloudTrailTools } from "./tools.js";

/** AWS CloudTrail: "what changed, who did it" — recent write activity and per-resource history. */
const createCloudTrailModule: ServiceModuleFactory = (factory) => {
  const mod: ServiceModule = {
    name: "cloudtrail",
    description:
      "AWS CloudTrail (read-only): recent write activity across the account and the change history of a single resource — who changed what, when, from where.",
    tools: buildCloudTrailTools(factory),
    healthCheck: async (ctx) => {
      try {
        const { client } = factory.getClient(CloudTrailClient, ctx.accountId, ctx.region);
        await client.send(new LookupEventsCommand({ MaxResults: 1 }));
        return { ok: true };
      } catch (err) {
        return { ok: false, detail: String(err) };
      }
    },
  };
  return mod;
};

export default createCloudTrailModule;
