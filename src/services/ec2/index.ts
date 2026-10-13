import { EC2Client, DescribeVpcsCommand } from "@aws-sdk/client-ec2";
import type { ServiceModule, ServiceModuleFactory } from "../../core/types.js";
import { buildEc2Tools } from "./tools.js";

/**
 * Amazon EC2 + VPC networking. Simple list/describe tools live in *.tool.md
 * next to this file and are appended by the registry.
 */
const createEc2Module: ServiceModuleFactory = (factory) => {
  const mod: ServiceModule = {
    name: "ec2",
    description:
      "Amazon EC2 + VPC networking: instances, VPCs, subnets, route tables, NAT gateways, VPC endpoints, security groups, network path tracing and open-port audits.",
    tools: buildEc2Tools(factory),
    healthCheck: async (ctx) => {
      try {
        const { client } = factory.getClient(EC2Client, ctx.accountId, ctx.region);
        await client.send(new DescribeVpcsCommand({ MaxResults: 5 }));
        return { ok: true };
      } catch (err) {
        return { ok: false, detail: String(err) };
      }
    },
  };
  return mod;
};

export default createEc2Module;
