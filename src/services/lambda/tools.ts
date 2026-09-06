import {
  LambdaClient,
  ListFunctionsCommand,
  GetFunctionConfigurationCommand,
} from "@aws-sdk/client-lambda";
import { CloudWatchClient, GetMetricStatisticsCommand } from "@aws-sdk/client-cloudwatch";
import { CloudWatchLogsClient, FilterLogEventsCommand } from "@aws-sdk/client-cloudwatch-logs";
import { z } from "zod";
import type { ToolDefinition, ToolContext } from "../../core/types.js";
import type { AwsClientFactory } from "../../core/aws-client.js";

/**
 * Lambda tools — read-only: function inventory, configuration, and error
 * triage (metrics + recent error logs in one call). No invoke, no updates.
 */
export function buildLambdaTools(factory: AwsClientFactory): ToolDefinition[] {
  const lambda = (ctx: ToolContext) => factory.getClient(LambdaClient, ctx.accountId, ctx.region).client;
  const cw = (ctx: ToolContext) => factory.getClient(CloudWatchClient, ctx.accountId, ctx.region).client;
  const logs = (ctx: ToolContext) => factory.getClient(CloudWatchLogsClient, ctx.accountId, ctx.region).client;

  /** Sum of one Lambda metric over the window (Errors, Invocations, Throttles). */
  async function metricSum(ctx: ToolContext, fn: string, metric: string, start: Date, end: Date): Promise<number> {
    const res = await cw(ctx).send(
      new GetMetricStatisticsCommand({
        Namespace: "AWS/Lambda",
        MetricName: metric,
        Dimensions: [{ Name: "FunctionName", Value: fn }],
        StartTime: start,
        EndTime: end,
        Period: 3600,
        Statistics: ["Sum"],
      }),
    );
    return (res.Datapoints ?? []).reduce((acc, p) => acc + (p.Sum ?? 0), 0);
  }

  return [
    {
      name: "list_functions",
      description: "List Lambda functions with runtime, memory, timeout, and last-modified date.",
      risk: "read",
      inputSchema: {
        limit: z.number().int().min(1).max(100).optional().describe("Max functions to return (default 50)"),
      },
      handler: async (args, ctx) => {
        const res = await lambda(ctx).send(
          new ListFunctionsCommand({ MaxItems: (args.limit as number | undefined) ?? 50 }),
        );
        const fns = res.Functions ?? [];
        return {
          count: fns.length,
          truncated: Boolean(res.NextMarker),
          functions: fns.map((f) => ({
            name: f.FunctionName,
            runtime: f.Runtime,
            memoryMB: f.MemorySize,
            timeoutSeconds: f.Timeout,
            lastModified: f.LastModified,
            codeSizeMB: f.CodeSize != null ? Number((f.CodeSize / 1e6).toFixed(1)) : undefined,
          })),
        };
      },
    },
    {
      name: "get_function_config",
      description:
        "Full configuration of one Lambda function: handler, role, architecture, state, and environment variable NAMES (values are never returned).",
      risk: "read",
      inputSchema: {
        functionName: z.string().max(170).describe("Function name or ARN"),
      },
      handler: async (args, ctx) => {
        const f = await lambda(ctx).send(
          new GetFunctionConfigurationCommand({ FunctionName: args.functionName as string }),
        );
        return {
          name: f.FunctionName,
          arn: f.FunctionArn,
          runtime: f.Runtime,
          handler: f.Handler,
          role: f.Role,
          architectures: f.Architectures,
          memoryMB: f.MemorySize,
          timeoutSeconds: f.Timeout,
          state: f.State,
          lastUpdateStatus: f.LastUpdateStatus,
          lastModified: f.LastModified,
          // Env var values may hold secrets — expose names only.
          envVarNames: Object.keys(f.Environment?.Variables ?? {}),
          deadLetterTarget: f.DeadLetterConfig?.TargetArn,
          layers: (f.Layers ?? []).map((l) => l.Arn),
        };
      },
    },
    {
      name: "function_errors",
      description:
        "Error triage for one Lambda function: invocation/error/throttle counts over a window plus the most recent error log lines (with stack traces).",
      risk: "read",
      inputSchema: {
        functionName: z.string().max(170).describe("Function name"),
        hours: z.number().min(0.25).max(72).optional().describe("Look-back window in hours (default 3)"),
        logLimit: z.number().int().min(1).max(50).optional().describe("Max error log events to return (default 10)"),
      },
      handler: async (args, ctx) => {
        const fn = args.functionName as string;
        const hours = (args.hours as number | undefined) ?? 3;
        const end = new Date();
        const start = new Date(end.getTime() - hours * 3600 * 1000);

        const [invocations, errors, throttles] = await Promise.all([
          metricSum(ctx, fn, "Invocations", start, end),
          metricSum(ctx, fn, "Errors", start, end),
          metricSum(ctx, fn, "Throttles", start, end),
        ]);

        // Pull the actual error lines from the function's log group.
        let errorLogs: { time?: string; message: string }[] = [];
        let logNote: string | undefined;
        try {
          const res = await logs(ctx).send(
            new FilterLogEventsCommand({
              logGroupName: `/aws/lambda/${fn}`,
              startTime: start.getTime(),
              filterPattern: "?ERROR ?Error ?Exception ?\"Task timed out\"",
              limit: (args.logLimit as number | undefined) ?? 10,
            }),
          );
          errorLogs = (res.events ?? []).map((e) => ({
            time: e.timestamp ? new Date(e.timestamp).toISOString() : undefined,
            message: (e.message ?? "").slice(0, 500),
          }));
        } catch (err) {
          logNote = `could not read log group: ${String(err).slice(0, 200)}`;
        }

        return {
          function: fn,
          window: { start: start.toISOString(), end: end.toISOString() },
          invocations,
          errors,
          throttles,
          errorRatePct: invocations > 0 ? Number(((errors / invocations) * 100).toFixed(2)) : 0,
          errorLogs,
          ...(logNote ? { logNote } : {}),
        };
      },
    },
  ];
}
