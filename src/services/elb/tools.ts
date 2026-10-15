import { ElasticLoadBalancingV2Client } from "@aws-sdk/client-elastic-load-balancing-v2";
import { z } from "zod";
import type { ToolDefinition, ToolContext } from "../../core/types.js";
import type { AwsClientFactory } from "../../core/aws-client.js";
import { findLoadBalancersForTarget, mapLoadBalancer } from "./describe.js";

/**
 * Multi-step ELB tools. Single-call tools (list LBs, listeners, target groups,
 * target health) are declared as *.tool.md files in this folder.
 */
export function buildElbTools(factory: AwsClientFactory): ToolDefinition[] {
  const elb = (ctx: ToolContext) => factory.getClient(ElasticLoadBalancingV2Client, ctx.accountId, ctx.region).client;

  return [
    {
      name: "map_load_balancer",
      description:
        "Full routing map of ONE load balancer in a single call: listeners (port/protocol/TLS) -> rules " +
        "(host/path conditions, priority) -> target groups -> every registered target (instance/IP) with its " +
        "health. Answers 'which endpoints/backends are behind this LB and are they healthy?'.",
      risk: "read",
      inputSchema: {
        name: z.string().max(32).describe("Load balancer name (from elb_list_load_balancers)"),
      },
      handler: async (args, ctx) => mapLoadBalancer(elb(ctx), args.name as string),
    },
    {
      name: "find_load_balancers_for_target",
      description:
        "Reverse lookup: which load balancers and target groups send traffic to a given EC2 instance id or IP " +
        "address, with the port and current health of that target in each group.",
      risk: "read",
      inputSchema: {
        target: z.string().max(64).describe("EC2 instance id (i-...) or private IP address"),
      },
      handler: async (args, ctx) => {
        const res = await findLoadBalancersForTarget(elb(ctx), args.target as string);
        return {
          target: args.target,
          behindLoadBalancers: res.matches.length > 0,
          ...res,
        };
      },
    },
  ];
}
