import {
  EC2Client,
  DescribeInstancesCommand,
  DescribeVpcsCommand,
  DescribeSubnetsCommand,
  DescribeRouteTablesCommand,
  DescribeSecurityGroupsCommand,
  DescribeNetworkInterfacesCommand,
  type SecurityGroup,
} from "@aws-sdk/client-ec2";
import { ElasticLoadBalancingV2Client } from "@aws-sdk/client-elastic-load-balancing-v2";
import { z } from "zod";
import type { ToolDefinition, ToolContext } from "../../core/types.js";
import type { AwsClientFactory } from "../../core/aws-client.js";
import { findLoadBalancersForTarget } from "../elb/describe.js";
import {
  defaultRoute,
  describeRoute,
  exposureVerdict,
  findWorldOpenRules,
  nameTag,
  routeTableForSubnet,
  summarizeRules,
} from "./network.js";

/**
 * Multi-step EC2/VPC tools. Single-call tools (list instances/VPCs/subnets,
 * route tables, gateways, security groups) are *.tool.md files in this folder.
 */
export function buildEc2Tools(factory: AwsClientFactory): ToolDefinition[] {
  const ec2 = (ctx: ToolContext) => factory.getClient(EC2Client, ctx.accountId, ctx.region).client;
  const elb = (ctx: ToolContext) => factory.getClient(ElasticLoadBalancingV2Client, ctx.accountId, ctx.region).client;

  return [
    {
      name: "trace_instance_network",
      description:
        "Explain an EC2 instance's network path in one call: VPC -> subnet -> the route table that actually " +
        "applies (explicit or the VPC main table) -> default route target (internet gateway / NAT / transit " +
        "gateway) -> security group rules -> load balancers in front of it -> a plain-English verdict on " +
        "whether it is reachable from the internet.",
      risk: "read",
      inputSchema: {
        instanceId: z.string().regex(/^i-[0-9a-f]+$/).describe("EC2 instance id, e.g. i-0abc123"),
      },
      handler: async (args, ctx) => {
        const client = ec2(ctx);
        const instanceId = args.instanceId as string;
        const inst = (await client.send(new DescribeInstancesCommand({ InstanceIds: [instanceId] }))).Reservations?.[0]
          ?.Instances?.[0];
        if (!inst) throw new Error(`Instance ${instanceId} not found.`);
        if (!inst.VpcId || !inst.SubnetId) {
          return { instanceId, state: inst.State?.Name, note: "Instance has no VPC/subnet (terminated or EC2-Classic)." };
        }

        const sgIds = (inst.SecurityGroups ?? []).map((g) => g.GroupId!).filter(Boolean);
        const [vpcs, subnets, tables, sgs] = await Promise.all([
          client.send(new DescribeVpcsCommand({ VpcIds: [inst.VpcId] })),
          client.send(new DescribeSubnetsCommand({ SubnetIds: [inst.SubnetId] })),
          client.send(new DescribeRouteTablesCommand({ Filters: [{ Name: "vpc-id", Values: [inst.VpcId] }] })),
          sgIds.length
            ? client.send(new DescribeSecurityGroupsCommand({ GroupIds: sgIds }))
            : Promise.resolve({ SecurityGroups: [] as SecurityGroup[] }),
        ]);
        const vpc = vpcs.Vpcs?.[0];
        const subnet = subnets.Subnets?.[0];
        const { table, association } = routeTableForSubnet(tables.RouteTables ?? [], inst.SubnetId);
        const route = defaultRoute(table);
        const groups = sgs.SecurityGroups ?? [];
        const worldOpen = groups.flatMap((g) =>
          findWorldOpenRules(g.IpPermissions).map((f) => ({ ...f, rule: `${f.rule} (${g.GroupId})` })),
        );

        // Best effort: ELB access may be denied while EC2 access is allowed.
        let loadBalancers: unknown;
        try {
          const ids = [instanceId, inst.PrivateIpAddress].filter((x): x is string => !!x);
          const found = await Promise.all(ids.map((id) => findLoadBalancersForTarget(elb(ctx), id)));
          loadBalancers = found.flatMap((f) => f.matches);
        } catch (err) {
          loadBalancers = { note: `Could not check load balancers: ${String(err).slice(0, 200)}` };
        }

        return {
          instance: {
            id: inst.InstanceId,
            name: nameTag(inst.Tags),
            state: inst.State?.Name,
            privateIp: inst.PrivateIpAddress,
            publicIp: inst.PublicIpAddress,
          },
          vpc: { id: vpc?.VpcId, name: nameTag(vpc?.Tags), cidr: vpc?.CidrBlock, isDefault: vpc?.IsDefault },
          subnet: {
            id: subnet?.SubnetId,
            name: nameTag(subnet?.Tags),
            cidr: subnet?.CidrBlock,
            az: subnet?.AvailabilityZone,
          },
          routeTable: {
            id: table?.RouteTableId,
            association,
            routes: (table?.Routes ?? []).map(describeRoute),
          },
          securityGroups: groups.map((g) => ({
            id: g.GroupId,
            name: g.GroupName,
            inbound: summarizeRules(g.IpPermissions, "from"),
            outbound: summarizeRules(g.IpPermissionsEgress, "to"),
          })),
          loadBalancers,
          verdict: exposureVerdict({ publicIp: inst.PublicIpAddress, defaultRoute: route, worldOpenInbound: worldOpen }),
        };
      },
    },
    {
      name: "find_open_security_groups",
      description:
        "Security audit: find security group rules open to the whole internet (0.0.0.0/0 or ::/0). Flags HIGH " +
        "severity for all-ports rules and sensitive ports (SSH 22, RDP 3389, MySQL 3306, PostgreSQL 5432, Redis, " +
        "MongoDB, ...), and shows how many network interfaces use each group (0 = unused, lower risk).",
      risk: "read",
      inputSchema: {
        vpcId: z.string().max(64).optional().describe("Only audit this VPC"),
        includeInfo: z
          .boolean()
          .optional()
          .describe("Also list expected public web rules (80/443). Default false."),
      },
      handler: async (args, ctx) => {
        const client = ec2(ctx);
        const groups: SecurityGroup[] = [];
        let NextToken: string | undefined;
        do {
          const res = await client.send(
            new DescribeSecurityGroupsCommand({
              Filters: args.vpcId ? [{ Name: "vpc-id", Values: [args.vpcId as string] }] : undefined,
              MaxResults: 1000,
              NextToken,
            }),
          );
          groups.push(...(res.SecurityGroups ?? []));
          NextToken = res.NextToken;
        } while (NextToken);

        const rank = { high: 0, medium: 1, info: 2 } as const;
        const flagged = groups
          .map((g) => ({
            group: g,
            findings: findWorldOpenRules(g.IpPermissions).filter((f) => args.includeInfo || f.severity !== "info"),
          }))
          .filter((x) => x.findings.length > 0);

        // How many ENIs use each flagged group (best effort).
        const usage = new Map<string, number>();
        try {
          const ids = flagged.map((x) => x.group.GroupId!);
          for (let i = 0; i < ids.length; i += 200) {
            const enis = await client.send(
              new DescribeNetworkInterfacesCommand({ Filters: [{ Name: "group-id", Values: ids.slice(i, i + 200) }] }),
            );
            for (const eni of enis.NetworkInterfaces ?? [])
              for (const g of eni.Groups ?? []) usage.set(g.GroupId!, (usage.get(g.GroupId!) ?? 0) + 1);
          }
        } catch {
          /* usage stays unknown */
        }

        const findings = flagged
          .flatMap(({ group, findings }) =>
            findings.map((f) => ({
              groupId: group.GroupId,
              groupName: group.GroupName,
              vpcId: group.VpcId,
              attachedInterfaces: usage.size ? (usage.get(group.GroupId!) ?? 0) : "unknown",
              ...f,
            })),
          )
          .sort((a, b) => rank[a.severity] - rank[b.severity]);

        return {
          groupsScanned: groups.length,
          high: findings.filter((f) => f.severity === "high").length,
          medium: findings.filter((f) => f.severity === "medium").length,
          findings: findings.slice(0, 100),
          truncated: findings.length > 100 || undefined,
        };
      },
    },
  ];
}
