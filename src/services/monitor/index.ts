import { CloudWatchClient, DescribeAlarmsCommand } from "@aws-sdk/client-cloudwatch";
import type { ServiceModule, ServiceModuleFactory } from "../../core/types.js";
import { buildMonitorTools } from "./tools.js";

/**
 * Monitor service module (read-only): evaluates ASG instance health and
 * CloudWatch alarm state and emits severity-tagged text alerts, so the LLM
 * can triage ("anything wrong?") instead of paging through raw inventories.
 */
const createMonitorModule: ServiceModuleFactory = (factory) => {
  const mod: ServiceModule = {
    name: "monitor",
    description:
      "Health checks that emit text alerts: detached/unhealthy ASG instances, capacity gaps, firing CloudWatch alarms (read-only).",
    tools: buildMonitorTools(factory),
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

export default createMonitorModule;
