import {
  ElasticLoadBalancingV2Client,
  DescribeLoadBalancersCommand,
  DescribeListenersCommand,
  DescribeRulesCommand,
  DescribeTargetGroupsCommand,
  DescribeTargetHealthCommand,
  type Rule,
} from "@aws-sdk/client-elastic-load-balancing-v2";
import { z } from "zod";
import type { ToolDefinition, ToolContext } from "../../core/types.js";
import type { AwsClientFactory } from "../../core/aws-client.js";
import {
  describeAction,
  describeConditions,
  findLoadBalancersForTarget,
  mapLimited,
  targetGroupArns,
} from "./describe.js";

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
      handler: async (args, ctx) => {
        const client = elb(ctx);
        const lbRes = await client.send(new DescribeLoadBalancersCommand({ Names: [args.name as string] }));
        const lb = lbRes.LoadBalancers?.[0];
        if (!lb) throw new Error(`Load balancer "${args.name}" not found.`);

        const listeners =
          (await client.send(new DescribeListenersCommand({ LoadBalancerArn: lb.LoadBalancerArn }))).Listeners ?? [];

        // Rules exist only for HTTP/HTTPS (ALB) listeners; NLB listeners have just a default action.
        const listenerViews = await mapLimited(listeners, 5, async (l) => {
          let rules: Rule[] = [];
          if (l.Protocol === "HTTP" || l.Protocol === "HTTPS") {
            rules = (await client.send(new DescribeRulesCommand({ ListenerArn: l.ListenerArn }))).Rules ?? [];
          }
          const ordered = [...rules].sort(
            (a, b) => (a.IsDefault ? 1 : 0) - (b.IsDefault ? 1 : 0) || Number(a.Priority) - Number(b.Priority),
          );
          return {
            listener: l,
            tgArns: [...targetGroupArns(l.DefaultActions), ...rules.flatMap((r) => targetGroupArns(r.Actions))],
            view: {
              port: l.Port,
              protocol: l.Protocol,
              certificates: l.Certificates?.map((c) => c.CertificateArn),
              rules: ordered.length
                ? ordered.map((r) => ({
                    priority: r.Priority,
                    when: describeConditions(r.Conditions),
                    then: (r.Actions ?? []).map(describeAction).join("; "),
                  }))
                : [{ priority: "default", when: "default (no conditions)", then: (l.DefaultActions ?? []).map(describeAction).join("; ") }],
            },
          };
        });

        const tgArns = [...new Set(listenerViews.flatMap((v) => v.tgArns))];
        const groups = [];
        for (let i = 0; i < tgArns.length; i += 20) {
          const res = await client.send(new DescribeTargetGroupsCommand({ TargetGroupArns: tgArns.slice(i, i + 20) }));
          groups.push(...(res.TargetGroups ?? []));
        }
        const targetGroups = await mapLimited(groups, 10, async (g) => {
          const health = (await client.send(new DescribeTargetHealthCommand({ TargetGroupArn: g.TargetGroupArn })))
            .TargetHealthDescriptions ?? [];
          const targets = health.map((d) => ({
            id: d.Target?.Id,
            port: d.Target?.Port,
            state: d.TargetHealth?.State,
            reason: d.TargetHealth?.Reason,
          }));
          return {
            name: g.TargetGroupName,
            protocol: g.Protocol,
            port: g.Port,
            targetType: g.TargetType,
            healthCheck: `${g.HealthCheckProtocol ?? ""} ${g.HealthCheckPort ?? ""} ${g.HealthCheckPath ?? ""}`.trim(),
            healthy: targets.filter((t) => t.state === "healthy").length,
            unhealthy: targets.filter((t) => t.state === "unhealthy").length,
            targets,
          };
        });

        return {
          loadBalancer: {
            name: lb.LoadBalancerName,
            type: lb.Type,
            scheme: lb.Scheme,
            state: lb.State?.Code,
            dns: lb.DNSName,
            vpcId: lb.VpcId,
            securityGroups: lb.SecurityGroups,
          },
          listeners: listenerViews.map((v) => v.view),
          targetGroups,
          warnings: targetGroups
            .filter((g) => g.targets.length === 0 || g.unhealthy > 0)
            .map((g) => (g.targets.length === 0 ? `${g.name}: no registered targets` : `${g.name}: ${g.unhealthy} unhealthy target(s)`)),
        };
      },
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
