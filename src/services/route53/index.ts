import { Route53Client, ListHostedZonesCommand } from "@aws-sdk/client-route-53";
import type { ServiceModule, ServiceModuleFactory } from "../../core/types.js";
import { buildRoute53Tools } from "./tools.js";

/** Amazon Route 53: hosted zones, records, and domain -> backend tracing. */
const createRoute53Module: ServiceModuleFactory = (factory) => {
  const mod: ServiceModule = {
    name: "route53",
    description:
      "Amazon Route 53 (read-only): hosted zones, DNS records, and end-to-end domain tracing (DNS -> load balancer -> targets, plus TLS certificate expiry).",
    tools: buildRoute53Tools(factory),
    healthCheck: async (ctx) => {
      try {
        const { client } = factory.getClient(Route53Client, ctx.accountId, "us-east-1");
        await client.send(new ListHostedZonesCommand({ MaxItems: 1 }));
        return { ok: true };
      } catch (err) {
        return { ok: false, detail: String(err) };
      }
    },
  };
  return mod;
};

export default createRoute53Module;
