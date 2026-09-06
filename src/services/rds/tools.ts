import { RDSClient, DescribeDBInstancesCommand } from "@aws-sdk/client-rds";
import { CloudWatchClient, GetMetricStatisticsCommand } from "@aws-sdk/client-cloudwatch";
import { z } from "zod";
import type { ToolDefinition, ToolContext } from "../../core/types.js";
import type { AwsClientFactory } from "../../core/aws-client.js";

/**
 * RDS tools — read-only: instance inventory (with security posture flags)
 * and key health metrics. No modify/reboot/delete.
 */
export function buildRdsTools(factory: AwsClientFactory): ToolDefinition[] {
  const rds = (ctx: ToolContext) => factory.getClient(RDSClient, ctx.accountId, ctx.region).client;
  const cw = (ctx: ToolContext) => factory.getClient(CloudWatchClient, ctx.accountId, ctx.region).client;

  return [
    {
      name: "list_db_instances",
      description:
        "List RDS instances: engine, class, status, storage, Multi-AZ, encryption, and whether they are publicly accessible (security flag).",
      risk: "read",
      inputSchema: {
        engine: z.string().max(50).optional().describe("Filter by engine, e.g. 'mysql', 'postgres'"),
      },
      handler: async (args, ctx) => {
        const res = await rds(ctx).send(new DescribeDBInstancesCommand({}));
        let instances = res.DBInstances ?? [];
        const engine = args.engine as string | undefined;
        if (engine) instances = instances.filter((d) => d.Engine === engine);
        return {
          count: instances.length,
          instances: instances.map((d) => ({
            id: d.DBInstanceIdentifier,
            engine: `${d.Engine} ${d.EngineVersion ?? ""}`.trim(),
            class: d.DBInstanceClass,
            status: d.DBInstanceStatus,
            storageGB: d.AllocatedStorage,
            multiAZ: d.MultiAZ,
            encrypted: d.StorageEncrypted,
            publiclyAccessible: d.PubliclyAccessible,
            endpoint: d.Endpoint?.Address,
            backupRetentionDays: d.BackupRetentionPeriod,
          })),
        };
      },
    },
    {
      name: "get_db_metrics",
      description:
        "Health metrics for one RDS instance over a window: CPU %, connections, free storage, freeable memory (latest value and average).",
      risk: "read",
      inputSchema: {
        dbInstanceId: z.string().max(63).describe("DB instance identifier"),
        hours: z.number().min(0.25).max(72).optional().describe("Look-back window in hours (default 3)"),
      },
      handler: async (args, ctx) => {
        const id = args.dbInstanceId as string;
        const hours = (args.hours as number | undefined) ?? 3;
        const end = new Date();
        const start = new Date(end.getTime() - hours * 3600 * 1000);

        const fetch = async (metric: string, transform: (v: number) => number = (v) => v) => {
          const res = await cw(ctx).send(
            new GetMetricStatisticsCommand({
              Namespace: "AWS/RDS",
              MetricName: metric,
              Dimensions: [{ Name: "DBInstanceIdentifier", Value: id }],
              StartTime: start,
              EndTime: end,
              Period: 300,
              Statistics: ["Average"],
            }),
          );
          const points = (res.Datapoints ?? []).sort(
            (a, b) => (a.Timestamp?.getTime() ?? 0) - (b.Timestamp?.getTime() ?? 0),
          );
          if (points.length === 0) return { latest: null, average: null };
          const values = points.map((p) => transform(p.Average ?? 0));
          return {
            latest: Number(values[values.length - 1].toFixed(2)),
            average: Number((values.reduce((a, v) => a + v, 0) / values.length).toFixed(2)),
          };
        };

        const toGB = (bytes: number) => bytes / 1e9;
        const [cpu, connections, freeStorageGB, freeableMemoryGB] = await Promise.all([
          fetch("CPUUtilization"),
          fetch("DatabaseConnections"),
          fetch("FreeStorageSpace", toGB),
          fetch("FreeableMemory", toGB),
        ]);

        return {
          dbInstanceId: id,
          window: { start: start.toISOString(), end: end.toISOString() },
          cpuPercent: cpu,
          connections,
          freeStorageGB,
          freeableMemoryGB,
        };
      },
    },
  ];
}
