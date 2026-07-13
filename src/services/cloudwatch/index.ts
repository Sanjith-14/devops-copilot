import { CloudWatchClient, DescribeAlarmsCommand } from "@aws-sdk/client-cloudwatch";
import type { ServiceModule, ServiceModuleFactory } from "../../core/types.js";
import { buildCloudWatchTools } from "./tools.js";

/**
 * CloudWatch service module (read-only): alarm inventory and state, alarm
 * history, metric discovery, and metric statistics.
 */
const createCloudWatchModule: ServiceModuleFactory = (factory) => {
  const mod: ServiceModule = {
    name: "cloudwatch",
    description:
      "Amazon CloudWatch: alarm inventory/state, alarm history, metric discovery, metric statistics (read-only).",
    tools: buildCloudWatchTools(factory),
    healthCheck: async (ctx) => {
      try {
        const { client } = factory.getClient(CloudWatchClient, ctx.accountId, ctx.region);
        await client.send(new DescribeAlarmsCommand({ MaxRecords: 1 }));
        return { ok: true };
      } catch (err) {
        return { ok: false, detail: String(err) };
      }
    },
  };
  return mod;
};

export default createCloudWatchModule;
