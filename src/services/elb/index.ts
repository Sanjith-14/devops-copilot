import { ElasticLoadBalancingV2Client, DescribeLoadBalancersCommand } from "@aws-sdk/client-elastic-load-balancing-v2";
import type { ServiceModule, ServiceModuleFactory } from "../../core/types.js";
import { buildElbTools } from "./tools.js";

/**
 * Elastic Load Balancing v2 (ALB/NLB). Simple list/describe tools live in
 * *.tool.md next to this file and are appended by the registry.
 */
const createElbModule: ServiceModuleFactory = (factory) => {
  const mod: ServiceModule = {
    name: "elb",
    description:
      "Elastic Load Balancing v2 (ALB/NLB): load balancers, listeners, rules, target groups, target health, and reverse lookup of which LB fronts an instance.",
    tools: buildElbTools(factory),
    healthCheck: async (ctx) => {
      try {
        const { client } = factory.getClient(ElasticLoadBalancingV2Client, ctx.accountId, ctx.region);
        await client.send(new DescribeLoadBalancersCommand({ PageSize: 1 }));
        return { ok: true };
      } catch (err) {
        return { ok: false, detail: String(err) };
      }
    },
  };
  return mod;
};

export default createElbModule;
