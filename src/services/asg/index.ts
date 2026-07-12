import { AutoScalingClient, DescribeAutoScalingGroupsCommand } from "@aws-sdk/client-auto-scaling";
import type { ServiceModule, ServiceModuleFactory } from "../../core/types.js";
import { buildAsgTools } from "./tools.js";

/**
 * EC2 Auto Scaling service module (read-only): group inventory, instance
 * lifecycle/health, scaling policies, and scaling activity history.
 */
const createAsgModule: ServiceModuleFactory = (factory) => {
  const mod: ServiceModule = {
    name: "asg",
    description:
      "EC2 Auto Scaling: group inventory, capacity settings, instance health, scaling policies and activity history (read-only).",
    tools: buildAsgTools(factory),
    healthCheck: async (ctx) => {
      try {
        const { client } = factory.getClient(AutoScalingClient, ctx.accountId, ctx.region);
        await client.send(new DescribeAutoScalingGroupsCommand({ MaxRecords: 1 }));
        return { ok: true };
      } catch (err) {
        return { ok: false, detail: String(err) };
      }
    },
  };
  return mod;
};

export default createAsgModule;
