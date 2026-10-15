import {
  EC2Client,
  DescribeVolumesCommand,
  DescribeAddressesCommand,
  DescribeSnapshotsCommand,
  type Volume,
  type Snapshot,
  type Address,
} from "@aws-sdk/client-ec2";
import { RDSClient, DescribeDBInstancesCommand } from "@aws-sdk/client-rds";
import { LambdaClient, ListFunctionsCommand } from "@aws-sdk/client-lambda";
import { CloudWatchClient, GetMetricStatisticsCommand } from "@aws-sdk/client-cloudwatch";
import { ElasticLoadBalancingV2Client, DescribeLoadBalancersCommand } from "@aws-sdk/client-elastic-load-balancing-v2";
import { z } from "zod";
import type { ToolDefinition, ToolContext } from "../../core/types.js";
import type { AwsClientFactory } from "../../core/aws-client.js";
import { bestEffort, daysSince, mapLimited } from "../../core/helpers.js";
import { allTargetGroups } from "../elb/describe.js";

/**
 * Approximate on-demand list prices (USD/month). Good enough to rank waste;
 * real prices vary by region (ap-south-1 is within ~10% of these).
 */
export const PRICES = {
  ebsPerGbMonth: { gp2: 0.1, gp3: 0.08, io1: 0.125, io2: 0.125, st1: 0.045, sc1: 0.015, standard: 0.05 } as Record<string, number>,
  snapshotPerGbMonth: 0.05,
  elasticIpMonth: 3.6,
  albMonth: 16.4,
};

const usd = (n: number) => Math.round(n * 100) / 100;

export interface WasteItem {
  resource: string;
  why: string;
  estMonthlyUSD?: number;
  [k: string]: unknown;
}

export const volumeWaste = (vols: Volume[], now = Date.now()): WasteItem[] =>
  vols
    .filter((v) => v.State === "available")
    .map((v) => ({
      resource: v.VolumeId!,
      why: `unattached ${v.VolumeType} volume (${v.Size} GB)`,
      ageDays: daysSince(v.CreateTime, now),
      estMonthlyUSD: usd((v.Size ?? 0) * (PRICES.ebsPerGbMonth[v.VolumeType ?? "gp2"] ?? 0.1)),
    }));

export const addressWaste = (addrs: Address[]): WasteItem[] =>
  addrs
    .filter((a) => !a.AssociationId)
    .map((a) => ({ resource: a.PublicIp ?? a.AllocationId!, why: "Elastic IP not attached to anything", estMonthlyUSD: PRICES.elasticIpMonth }));

export const snapshotWaste = (snaps: Snapshot[], olderThanDays: number, now = Date.now()): WasteItem[] =>
  snaps
    .map((s) => ({ s, age: daysSince(s.StartTime, now) ?? 0 }))
    .filter(({ age }) => age > olderThanDays)
    .map(({ s, age }) => ({
      resource: s.SnapshotId!,
      why: `snapshot ${age} days old (${s.VolumeSize} GB source volume)`,
      description: s.Description?.slice(0, 80),
      // Upper bound: snapshots are incremental, real stored size is usually smaller.
      estMonthlyUSD: usd((s.VolumeSize ?? 0) * PRICES.snapshotPerGbMonth),
    }));

export function buildWasteTools(factory: AwsClientFactory): ToolDefinition[] {
  const get = <T>(Ctor: new (c: never) => T, ctx: ToolContext) =>
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    factory.getClient(Ctor as any, ctx.accountId, ctx.region).client as T;

  const metric = async (ctx: ToolContext, ns: string, name: string, dim: { Name: string; Value: string }, days: number, stat: "Average" | "Maximum" | "Sum") => {
    const end = new Date();
    const res = await get(CloudWatchClient, ctx).send(
      new GetMetricStatisticsCommand({
        Namespace: ns,
        MetricName: name,
        Dimensions: [dim],
        StartTime: new Date(end.getTime() - days * 86_400_000),
        EndTime: end,
        Period: days * 86_400,
        Statistics: [stat],
      }),
    );
    const p = res.Datapoints?.[0];
    return p ? (p[stat] ?? 0) : undefined;
  };

  return [
    {
      name: "find_waste",
      description:
        "Find resources you are probably paying for without using, with an approximate monthly cost: unattached EBS " +
        "volumes, unused Elastic IPs, old EBS snapshots, idle RDS instances (low CPU and zero connections), load " +
        "balancers with no registered targets, and Lambda functions with zero invocations. Read-only — it only " +
        "reports; prices are approximate list prices. Sections without permission are reported as skipped.",
      risk: "read",
      inputSchema: {
        snapshotAgeDays: z.number().int().min(7).max(3650).optional().describe("Report snapshots older than this (default 180)"),
        idleDays: z.number().int().min(1).max(30).optional().describe("Window for idle RDS / unused Lambda checks (default 14)"),
      },
      handler: async (args, ctx) => {
        const snapshotAge = (args.snapshotAgeDays as number | undefined) ?? 180;
        const idleDays = (args.idleDays as number | undefined) ?? 14;
        const ec2 = get(EC2Client, ctx);

        const [volumes, elasticIps, snapshots, idleRds, emptyLoadBalancers, unusedLambdas] = await Promise.all([
          bestEffort(async () => {
            const vols: Volume[] = [];
            let NextToken: string | undefined;
            do {
              const r = await ec2.send(new DescribeVolumesCommand({ Filters: [{ Name: "status", Values: ["available"] }], MaxResults: 500, NextToken }));
              vols.push(...(r.Volumes ?? []));
              NextToken = r.NextToken;
            } while (NextToken);
            return volumeWaste(vols);
          }),
          bestEffort(async () => addressWaste((await ec2.send(new DescribeAddressesCommand({}))).Addresses ?? [])),
          bestEffort(async () => {
            const snaps: Snapshot[] = [];
            let NextToken: string | undefined;
            do {
              const r = await ec2.send(new DescribeSnapshotsCommand({ OwnerIds: ["self"], MaxResults: 1000, NextToken }));
              snaps.push(...(r.Snapshots ?? []));
              NextToken = r.NextToken;
            } while (NextToken && snaps.length < 5000);
            return snapshotWaste(snaps, snapshotAge);
          }),
          bestEffort(async () => {
            const dbs = (await get(RDSClient, ctx).send(new DescribeDBInstancesCommand({}))).DBInstances ?? [];
            const checked = await mapLimited(dbs.filter((d) => d.DBInstanceStatus === "available"), 5, async (d) => {
              const dim = { Name: "DBInstanceIdentifier", Value: d.DBInstanceIdentifier! };
              const [cpu, conns] = await Promise.all([
                metric(ctx, "AWS/RDS", "CPUUtilization", dim, idleDays, "Average"),
                metric(ctx, "AWS/RDS", "DatabaseConnections", dim, idleDays, "Maximum"),
              ]);
              return { d, cpu, conns };
            });
            return checked
              .filter(({ cpu, conns }) => conns === 0 && (cpu ?? 0) < 5)
              .map(({ d, cpu }): WasteItem => ({
                resource: `rds:${d.DBInstanceIdentifier}`,
                why: `no connections in ${idleDays} days (avg CPU ${cpu?.toFixed(1) ?? "?"}%) — ${d.DBInstanceClass}`,
              }));
          }),
          bestEffort(async () => {
            const elb = get(ElasticLoadBalancingV2Client, ctx);
            const lbs = (await elb.send(new DescribeLoadBalancersCommand({ PageSize: 400 }))).LoadBalancers ?? [];
            const used = new Set((await allTargetGroups(elb)).flatMap((g) => g.LoadBalancerArns ?? []));
            return lbs
              .filter((lb) => lb.Type !== "gateway" && !used.has(lb.LoadBalancerArn!))
              .map((lb): WasteItem => ({
                resource: `elb:${lb.LoadBalancerName}`,
                why: `${lb.Type} load balancer with no target groups attached`,
                estMonthlyUSD: PRICES.albMonth,
              }));
          }),
          bestEffort(async () => {
            const fns = ((await get(LambdaClient, ctx).send(new ListFunctionsCommand({ MaxItems: 200 }))).Functions ?? []).slice(0, 200);
            const checked = await mapLimited(fns, 10, async (f) => ({
              f,
              invocations: await metric(ctx, "AWS/Lambda", "Invocations", { Name: "FunctionName", Value: f.FunctionName! }, idleDays, "Sum"),
            }));
            return checked
              .filter(({ invocations }) => !invocations)
              .map(({ f }): WasteItem => ({
                resource: `lambda:${f.FunctionName}`,
                why: `zero invocations in ${idleDays} days (last modified ${f.LastModified?.slice(0, 10)})`,
              }));
          }),
        ]);

        const sections = { volumes, elasticIps, snapshots, idleRds, emptyLoadBalancers, unusedLambdas };
        const items = Object.values(sections).flatMap((s) => (s.status === "checked" ? s.data : []));
        const total = usd(items.reduce((n, i) => n + (i.estMonthlyUSD ?? 0), 0));

        return {
          estimatedMonthlyWasteUSD: total,
          summary: Object.fromEntries(
            Object.entries(sections).map(([k, s]) => [
              k,
              s.status === "checked"
                ? { count: s.data.length, estMonthlyUSD: usd(s.data.reduce((n, i) => n + (i.estMonthlyUSD ?? 0), 0)) }
                : { skipped: s.reason },
            ]),
          ),
          items: items.sort((a, b) => (b.estMonthlyUSD ?? 0) - (a.estMonthlyUSD ?? 0)).slice(0, 100),
          truncated: items.length > 100 || undefined,
          note: "Estimates use approximate list prices. Idle RDS and unused Lambda have no estimate (depends on class/usage). Verify before deleting anything.",
        };
      },
    },
  ];
}
