import {
  CloudWatchClient,
  DescribeAlarmsCommand,
  DescribeAlarmHistoryCommand,
  ListMetricsCommand,
  GetMetricStatisticsCommand,
  type AlarmType,
  type HistoryItemType,
  type StateValue,
  type Statistic,
} from "@aws-sdk/client-cloudwatch";
import { CloudWatchLogsClient, FilterLogEventsCommand, DescribeLogGroupsCommand } from "@aws-sdk/client-cloudwatch-logs";
import { z } from "zod";
import type { ToolDefinition, ToolContext } from "../../core/types.js";
import type { AwsClientFactory } from "../../core/aws-client.js";

/** Parse "Name=Value" dimension strings into the SDK shape. */
function parseDimensions(dims?: string[]): { Name: string; Value: string }[] | undefined {
  if (!dims?.length) return undefined;
  return dims.map((d) => {
    const idx = d.indexOf("=");
    if (idx < 1) throw new Error(`Invalid dimension "${d}", expected "Name=Value"`);
    return { Name: d.slice(0, idx), Value: d.slice(idx + 1) };
  });
}

/**
 * CloudWatch tools — read-only by design: alarm inventory/state, alarm
 * history, metric discovery, and metric statistics. No PutMetricAlarm,
 * no SetAlarmState.
 */
export function buildCloudWatchTools(factory: AwsClientFactory): ToolDefinition[] {
  const cw = (ctx: ToolContext) => factory.getClient(CloudWatchClient, ctx.accountId, ctx.region).client;
  const logs = (ctx: ToolContext) => factory.getClient(CloudWatchLogsClient, ctx.accountId, ctx.region).client;

  return [
    {
      name: "list_log_groups",
      description: "List CloudWatch log groups, optionally filtered by name prefix, with retention and size.",
      risk: "read",
      inputSchema: {
        namePrefix: z.string().max(512).optional().describe("Log group name prefix, e.g. '/aws/lambda/'"),
        limit: z.number().int().min(1).max(50).optional().describe("Max groups to return (default 25)"),
      },
      handler: async (args, ctx) => {
        const res = await logs(ctx).send(
          new DescribeLogGroupsCommand({
            logGroupNamePrefix: args.namePrefix as string | undefined,
            limit: (args.limit as number | undefined) ?? 25,
          }),
        );
        const groups = res.logGroups ?? [];
        return {
          count: groups.length,
          truncated: Boolean(res.nextToken),
          logGroups: groups.map((g) => ({
            name: g.logGroupName,
            retentionDays: g.retentionInDays ?? "never expires",
            storedMB: g.storedBytes != null ? Number((g.storedBytes / 1e6).toFixed(1)) : undefined,
          })),
        };
      },
    },
    {
      name: "tail_log_group",
      description:
        "Fetch recent events from a CloudWatch log group (like `tail`), optionally filtered by a pattern (e.g. 'ERROR' or '?timeout ?Timeout'). Messages are truncated to 500 chars each.",
      risk: "read",
      inputSchema: {
        logGroup: z.string().max(512).describe("Log group name, e.g. '/aws/lambda/my-fn'"),
        minutes: z.number().int().min(1).max(1440).optional().describe("Look-back window in minutes (default 15)"),
        filterPattern: z
          .string()
          .max(1024)
          .optional()
          .describe("CloudWatch Logs filter pattern, e.g. 'ERROR' — omit for all events"),
        limit: z.number().int().min(1).max(200).optional().describe("Max events to return (default 50)"),
      },
      handler: async (args, ctx) => {
        const minutes = (args.minutes as number | undefined) ?? 15;
        const res = await logs(ctx).send(
          new FilterLogEventsCommand({
            logGroupName: args.logGroup as string,
            startTime: Date.now() - minutes * 60_000,
            filterPattern: args.filterPattern as string | undefined,
            limit: (args.limit as number | undefined) ?? 50,
          }),
        );
        const events = res.events ?? [];
        return {
          logGroup: args.logGroup,
          windowMinutes: minutes,
          count: events.length,
          truncated: Boolean(res.nextToken),
          events: events.map((e) => ({
            time: e.timestamp ? new Date(e.timestamp).toISOString() : undefined,
            stream: e.logStreamName,
            // Hard cap per message: raw app logs can be huge and would flood the LLM context.
            message: (e.message ?? "").slice(0, 500),
          })),
        };
      },
    },
    {
      name: "list_alarms",
      description:
        "List CloudWatch alarms with current state (OK / ALARM / INSUFFICIENT_DATA), the metric they watch, and threshold. Filter by state or name prefix.",
      risk: "read",
      inputSchema: {
        state: z
          .enum(["OK", "ALARM", "INSUFFICIENT_DATA"])
          .optional()
          .describe("Only alarms currently in this state. Omit for all."),
        namePrefix: z.string().optional().describe("Filter alarms whose name starts with this prefix."),
        limit: z.number().int().min(1).max(100).optional().describe("Max alarms to return (default 50)"),
      },
      handler: async (args, ctx) => {
        const res = await cw(ctx).send(
          new DescribeAlarmsCommand({
            StateValue: args.state as StateValue | undefined,
            AlarmNamePrefix: args.namePrefix as string | undefined,
            MaxRecords: (args.limit as number | undefined) ?? 50,
            AlarmTypes: ["MetricAlarm", "CompositeAlarm"] as AlarmType[],
          }),
        );
        const metric = res.MetricAlarms ?? [];
        const composite = res.CompositeAlarms ?? [];
        return {
          count: metric.length + composite.length,
          truncated: Boolean(res.NextToken),
          alarms: [
            ...metric.map((a) => ({
              name: a.AlarmName,
              state: a.StateValue,
              stateReason: a.StateReason,
              stateSince: a.StateUpdatedTimestamp,
              namespace: a.Namespace,
              metric: a.MetricName,
              dimensions: (a.Dimensions ?? []).map((d) => `${d.Name}=${d.Value}`),
              comparison: `${a.Statistic ?? a.ExtendedStatistic ?? ""} ${a.ComparisonOperator} ${a.Threshold}`,
              periodSeconds: a.Period,
              evaluationPeriods: a.EvaluationPeriods,
              actionsEnabled: a.ActionsEnabled,
            })),
            ...composite.map((a) => ({
              name: a.AlarmName,
              state: a.StateValue,
              stateReason: a.StateReason,
              stateSince: a.StateUpdatedTimestamp,
              type: "composite",
              rule: a.AlarmRule,
              actionsEnabled: a.ActionsEnabled,
            })),
          ],
        };
      },
    },
    {
      name: "get_alarm_history",
      description:
        "State-change history for one alarm: when it flipped between OK/ALARM, why, and any actions taken.",
      risk: "read",
      inputSchema: {
        alarm: z.string().describe("Alarm name"),
        historyType: z
          .enum(["StateUpdate", "Action", "ConfigurationUpdate"])
          .optional()
          .describe("Filter by history item type (default: all)"),
        limit: z.number().int().min(1).max(100).optional().describe("Max items to return (default 20)"),
      },
      handler: async (args, ctx) => {
        const res = await cw(ctx).send(
          new DescribeAlarmHistoryCommand({
            AlarmName: args.alarm as string,
            HistoryItemType: args.historyType as HistoryItemType | undefined,
            MaxRecords: (args.limit as number | undefined) ?? 20,
          }),
        );
        const items = res.AlarmHistoryItems ?? [];
        return {
          alarm: args.alarm,
          count: items.length,
          history: items.map((h) => ({
            timestamp: h.Timestamp,
            type: h.HistoryItemType,
            summary: h.HistorySummary,
          })),
        };
      },
    },
    {
      name: "list_metrics",
      description:
        "Discover available metrics, optionally filtered by namespace (e.g. AWS/EC2, AWS/S3, AWS/AutoScaling) and metric name.",
      risk: "read",
      inputSchema: {
        namespace: z.string().optional().describe("Metric namespace, e.g. 'AWS/EC2'. Omit for all."),
        metricName: z.string().optional().describe("Exact metric name filter, e.g. 'CPUUtilization'."),
        limit: z.number().int().min(1).max(200).optional().describe("Max metrics to return (default 100)"),
      },
      handler: async (args, ctx) => {
        const res = await cw(ctx).send(
          new ListMetricsCommand({
            Namespace: args.namespace as string | undefined,
            MetricName: args.metricName as string | undefined,
          }),
        );
        const limit = (args.limit as number | undefined) ?? 100;
        const metrics = (res.Metrics ?? []).slice(0, limit);
        return {
          count: metrics.length,
          truncated: Boolean(res.NextToken) || (res.Metrics?.length ?? 0) > limit,
          metrics: metrics.map((m) => ({
            namespace: m.Namespace,
            name: m.MetricName,
            dimensions: (m.Dimensions ?? []).map((d) => `${d.Name}=${d.Value}`),
          })),
        };
      },
    },
    {
      name: "get_metric_statistics",
      description:
        "Fetch datapoints for one metric over a time window (default: last 3 hours, 5-minute periods). Use list_metrics first to find namespace/name/dimensions.",
      risk: "read",
      inputSchema: {
        namespace: z.string().describe("Metric namespace, e.g. 'AWS/EC2'"),
        metricName: z.string().describe("Metric name, e.g. 'CPUUtilization'"),
        dimensions: z
          .array(z.string())
          .optional()
          .describe("Dimensions as 'Name=Value', e.g. ['InstanceId=i-0abc123']"),
        statistic: z
          .enum(["Average", "Sum", "Minimum", "Maximum", "SampleCount"])
          .optional()
          .describe("Statistic to fetch (default Average)"),
        hours: z.number().min(0.25).max(336).optional().describe("Look-back window in hours (default 3, max 14 days)"),
        periodSeconds: z
          .number()
          .int()
          .min(60)
          .optional()
          .describe("Datapoint granularity in seconds, multiple of 60 (default 300)"),
      },
      handler: async (args, ctx) => {
        const hours = (args.hours as number | undefined) ?? 3;
        const end = new Date();
        const start = new Date(end.getTime() - hours * 3600 * 1000);
        const statistic = ((args.statistic as string | undefined) ?? "Average") as Statistic;

        const res = await cw(ctx).send(
          new GetMetricStatisticsCommand({
            Namespace: args.namespace as string,
            MetricName: args.metricName as string,
            Dimensions: parseDimensions(args.dimensions as string[] | undefined),
            StartTime: start,
            EndTime: end,
            Period: (args.periodSeconds as number | undefined) ?? 300,
            Statistics: [statistic],
          }),
        );
        const points = (res.Datapoints ?? []).sort(
          (a, b) => (a.Timestamp?.getTime() ?? 0) - (b.Timestamp?.getTime() ?? 0),
        );
        return {
          metric: `${args.namespace}/${args.metricName}`,
          statistic,
          window: { start: start.toISOString(), end: end.toISOString() },
          count: points.length,
          unit: points[0]?.Unit,
          datapoints: points.map((p) => ({
            time: p.Timestamp,
            value: p[statistic as "Average" | "Sum" | "Minimum" | "Maximum" | "SampleCount"],
          })),
        };
      },
    },
  ];
}
