import { DynamoDBClient, ListTablesCommand, DescribeTableCommand } from "@aws-sdk/client-dynamodb";
import { CloudWatchClient, GetMetricStatisticsCommand } from "@aws-sdk/client-cloudwatch";
import { z } from "zod";
import type { ToolDefinition, ToolContext } from "../../core/types.js";
import type { AwsClientFactory } from "../../core/aws-client.js";

/**
 * DynamoDB tools — read-only: table inventory, table details, and throttle
 * checks. No item reads (data plane stays off-limits), no writes.
 */
export function buildDynamoDbTools(factory: AwsClientFactory): ToolDefinition[] {
  const ddb = (ctx: ToolContext) => factory.getClient(DynamoDBClient, ctx.accountId, ctx.region).client;
  const cw = (ctx: ToolContext) => factory.getClient(CloudWatchClient, ctx.accountId, ctx.region).client;

  return [
    {
      name: "list_tables",
      description: "List DynamoDB table names in the account/region.",
      risk: "read",
      inputSchema: {
        limit: z.number().int().min(1).max(100).optional().describe("Max tables to return (default 50)"),
      },
      handler: async (args, ctx) => {
        const res = await ddb(ctx).send(
          new ListTablesCommand({ Limit: (args.limit as number | undefined) ?? 50 }),
        );
        return {
          count: res.TableNames?.length ?? 0,
          truncated: Boolean(res.LastEvaluatedTableName),
          tables: res.TableNames ?? [],
        };
      },
    },
    {
      name: "describe_table",
      description:
        "Details of one DynamoDB table: status, billing mode, size, item count, key schema, indexes, and provisioned throughput.",
      risk: "read",
      inputSchema: {
        table: z.string().max(255).describe("Table name"),
      },
      handler: async (args, ctx) => {
        const res = await ddb(ctx).send(new DescribeTableCommand({ TableName: args.table as string }));
        const t = res.Table;
        return {
          name: t?.TableName,
          status: t?.TableStatus,
          billingMode: t?.BillingModeSummary?.BillingMode ?? "PROVISIONED",
          itemCount: t?.ItemCount,
          sizeMB: t?.TableSizeBytes != null ? Number((t.TableSizeBytes / 1e6).toFixed(1)) : undefined,
          keySchema: (t?.KeySchema ?? []).map((k) => `${k.AttributeName} (${k.KeyType})`),
          provisioned: t?.ProvisionedThroughput?.ReadCapacityUnits
            ? {
                readCapacity: t.ProvisionedThroughput.ReadCapacityUnits,
                writeCapacity: t.ProvisionedThroughput.WriteCapacityUnits,
              }
            : undefined,
          globalIndexes: (t?.GlobalSecondaryIndexes ?? []).map((g) => g.IndexName),
          created: t?.CreationDateTime,
        };
      },
    },
    {
      name: "check_table_throttling",
      description:
        "Check one table for read/write throttle events over a window — nonzero counts mean capacity is too low for the traffic.",
      risk: "read",
      inputSchema: {
        table: z.string().max(255).describe("Table name"),
        hours: z.number().min(0.25).max(72).optional().describe("Look-back window in hours (default 3)"),
      },
      handler: async (args, ctx) => {
        const table = args.table as string;
        const hours = (args.hours as number | undefined) ?? 3;
        const end = new Date();
        const start = new Date(end.getTime() - hours * 3600 * 1000);

        const sum = async (metric: string) => {
          const res = await cw(ctx).send(
            new GetMetricStatisticsCommand({
              Namespace: "AWS/DynamoDB",
              MetricName: metric,
              Dimensions: [{ Name: "TableName", Value: table }],
              StartTime: start,
              EndTime: end,
              Period: 3600,
              Statistics: ["Sum"],
            }),
          );
          return (res.Datapoints ?? []).reduce((acc, p) => acc + (p.Sum ?? 0), 0);
        };

        const [readThrottles, writeThrottles] = await Promise.all([
          sum("ReadThrottleEvents"),
          sum("WriteThrottleEvents"),
        ]);

        return {
          table,
          window: { start: start.toISOString(), end: end.toISOString() },
          readThrottles,
          writeThrottles,
          healthy: readThrottles === 0 && writeThrottles === 0,
        };
      },
    },
  ];
}
