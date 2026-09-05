import { CostExplorerClient, GetCostAndUsageCommand } from "@aws-sdk/client-cost-explorer";
import type { ServiceModule, ServiceModuleFactory } from "../../core/types.js";
import { buildCostTools } from "./tools.js";

/**
 * Cost service module (read-only): daily spend breakdowns plus cost-anomaly
 * detection — both AWS-native (Cost Anomaly Detection) and a statistical
 * spike check that emits severity-tagged text alerts.
 */
const createCostModule: ServiceModuleFactory = (factory) => {
  const mod: ServiceModule = {
    name: "cost",
    description:
      "AWS spend: daily cost by service, statistical spend-spike alerts, and AWS Cost Anomaly Detection results (read-only).",
    tools: buildCostTools(factory),
    healthCheck: async (ctx) => {
      try {
        // Cost Explorer is global; always served from us-east-1.
        const { client } = factory.getClient(CostExplorerClient, ctx.accountId, "us-east-1");
        const end = new Date().toISOString().slice(0, 10);
        const startDate = new Date();
        startDate.setUTCDate(startDate.getUTCDate() - 1);
        await client.send(
          new GetCostAndUsageCommand({
            TimePeriod: { Start: startDate.toISOString().slice(0, 10), End: end },
            Granularity: "DAILY",
            Metrics: ["UnblendedCost"],
          }),
        );
        return { ok: true };
      } catch (err) {
        return { ok: false, detail: String(err) };
      }
    },
  };
  return mod;
};

export default createCostModule;
