import {
  CostExplorerClient,
  GetCostAndUsageCommand,
  GetAnomaliesCommand,
} from "@aws-sdk/client-cost-explorer";
import { z } from "zod";
import type { ToolDefinition, ToolContext } from "../../core/types.js";
import type { AwsClientFactory } from "../../core/aws-client.js";

/** Cost Explorer is a global service served from us-east-1 regardless of workload region. */
const CE_REGION = "us-east-1";

function isoDate(d: Date): string {
  return d.toISOString().slice(0, 10);
}

/** Days ago at midnight UTC, as YYYY-MM-DD (Cost Explorer granularity). */
function daysAgo(n: number): string {
  const d = new Date();
  d.setUTCDate(d.getUTCDate() - n);
  return isoDate(d);
}

/** Fetch daily cost per service for the trailing window. Map: service -> [cost per day, oldest first]. */
async function dailyCostByService(
  client: CostExplorerClient,
  days: number,
): Promise<{ dates: string[]; byService: Map<string, number[]> }> {
  const dates: string[] = [];
  const byService = new Map<string, number[]>();
  let token: string | undefined;
  let dayIndex = 0;

  do {
    const res = await client.send(
      new GetCostAndUsageCommand({
        TimePeriod: { Start: daysAgo(days), End: daysAgo(0) },
        Granularity: "DAILY",
        Metrics: ["UnblendedCost"],
        GroupBy: [{ Type: "DIMENSION", Key: "SERVICE" }],
        NextPageToken: token,
      }),
    );
    for (const day of res.ResultsByTime ?? []) {
      dates.push(day.TimePeriod?.Start ?? "?");
      for (const group of day.Groups ?? []) {
        const service = group.Keys?.[0] ?? "?";
        const cost = Number(group.Metrics?.UnblendedCost?.Amount ?? 0);
        let series = byService.get(service);
        if (!series) {
          series = [];
          byService.set(service, series);
        }
        series[dayIndex] = cost;
      }
      dayIndex++;
    }
    token = res.NextPageToken;
  } while (token);

  // Missing days = zero spend, not missing data.
  for (const series of byService.values()) {
    for (let i = 0; i < dayIndex; i++) series[i] = series[i] ?? 0;
  }
  return { dates, byService };
}

export function buildCostTools(factory: AwsClientFactory): ToolDefinition[] {
  const ce = (ctx: ToolContext) => factory.getClient(CostExplorerClient, ctx.accountId, CE_REGION).client;

  return [
    {
      name: "daily_spend",
      description:
        "Daily AWS spend (UnblendedCost, USD) for the last N days, with per-service breakdown and totals. Note: each Cost Explorer API call costs $0.01.",
      risk: "read",
      inputSchema: {
        days: z.number().int().min(2).max(90).optional().describe("Trailing window in days (default 7)"),
        topServices: z.number().int().min(1).max(50).optional().describe("How many top services to include (default 10)"),
      },
      handler: async (args, ctx) => {
        const days = (args.days as number | undefined) ?? 7;
        const top = (args.topServices as number | undefined) ?? 10;
        const { dates, byService } = await dailyCostByService(ce(ctx), days);

        const services = [...byService.entries()]
          .map(([service, series]) => ({
            service,
            totalUsd: Number(series.reduce((a, b) => a + b, 0).toFixed(2)),
            dailyUsd: series.map((v) => Number(v.toFixed(2))),
          }))
          .sort((a, b) => b.totalUsd - a.totalUsd);

        const dailyTotals = dates.map((_, i) =>
          Number([...byService.values()].reduce((sum, s) => sum + (s[i] ?? 0), 0).toFixed(2)),
        );

        return {
          window: { start: dates[0], end: dates[dates.length - 1], days },
          totalUsd: Number(dailyTotals.reduce((a, b) => a + b, 0).toFixed(2)),
          dailyTotalsUsd: dates.map((date, i) => ({ date, usd: dailyTotals[i] })),
          topServices: services.slice(0, top),
          otherServicesCount: Math.max(0, services.length - top),
        };
      },
    },
    {
      name: "detect_spend_spikes",
      description:
        "Statistical cost-anomaly check: compares each service's most recent full day against its trailing baseline (mean + stddev) and emits text alerts for spikes. Read the alerts and decide whether to investigate. Note: each Cost Explorer API call costs $0.01.",
      risk: "read",
      inputSchema: {
        baselineDays: z.number().int().min(7).max(90).optional().describe("Baseline window in days (default 14)"),
        sensitivity: z
          .number()
          .min(1)
          .max(10)
          .optional()
          .describe("Stddev multiplier for the spike threshold (default 3 — lower = more alerts)"),
        minImpactUsd: z
          .number()
          .min(0)
          .optional()
          .describe("Ignore spikes smaller than this many dollars/day (default 1)"),
      },
      handler: async (args, ctx) => {
        const days = (args.baselineDays as number | undefined) ?? 14;
        const k = (args.sensitivity as number | undefined) ?? 3;
        const minImpact = (args.minImpactUsd as number | undefined) ?? 1;
        const { dates, byService } = await dailyCostByService(ce(ctx), days);

        const alerts: { severity: "critical" | "warning"; message: string }[] = [];
        for (const [service, series] of byService) {
          if (series.length < 3) continue;
          const latest = series[series.length - 1];
          const baseline = series.slice(0, -1);
          const mean = baseline.reduce((a, b) => a + b, 0) / baseline.length;
          const variance = baseline.reduce((a, b) => a + (b - mean) ** 2, 0) / baseline.length;
          const std = Math.sqrt(variance);
          const threshold = mean + k * std;

          if (latest > threshold && latest - mean >= minImpact) {
            const pct = mean > 0 ? Math.round(((latest - mean) / mean) * 100) : Infinity;
            alerts.push({
              severity: latest - mean >= 10 * minImpact ? "critical" : "warning",
              message:
                `Cost spike in "${service}" on ${dates[dates.length - 1]}: $${latest.toFixed(2)} vs ` +
                `baseline avg $${mean.toFixed(2)}/day (${pct === Infinity ? "new spend" : `+${pct}%`}, ` +
                `threshold $${threshold.toFixed(2)}).`,
            });
          }
        }
        alerts.sort((a) => (a.severity === "critical" ? -1 : 1));

        return {
          status: alerts.some((a) => a.severity === "critical") ? "CRITICAL" : alerts.length > 0 ? "WARNING" : "OK",
          window: { start: dates[0], end: dates[dates.length - 1], baselineDays: days, sensitivity: k },
          alertCount: alerts.length,
          summary:
            alerts.length === 0
              ? "No cost anomalies detected — spend is within the normal baseline."
              : alerts.map((a) => `[${a.severity.toUpperCase()}] ${a.message}`).join("\n"),
          alerts,
        };
      },
    },
    {
      name: "get_aws_anomalies",
      description:
        "Fetch anomalies from AWS Cost Anomaly Detection (requires anomaly monitors configured in the account): impact in USD, root-cause service/account, and time range.",
      risk: "read",
      inputSchema: {
        days: z.number().int().min(1).max(90).optional().describe("Look-back window in days (default 30)"),
        minImpactUsd: z.number().min(0).optional().describe("Only anomalies with at least this total impact (default 0)"),
      },
      handler: async (args, ctx) => {
        const days = (args.days as number | undefined) ?? 30;
        const res = await ce(ctx).send(
          new GetAnomaliesCommand({
            DateInterval: { StartDate: daysAgo(days), EndDate: daysAgo(0) },
            TotalImpact: args.minImpactUsd
              ? { NumericOperator: "GREATER_THAN_OR_EQUAL", StartValue: args.minImpactUsd as number }
              : undefined,
          }),
        );
        const anomalies = res.Anomalies ?? [];
        return {
          count: anomalies.length,
          anomalies: anomalies.map((a) => ({
            start: a.AnomalyStartDate,
            end: a.AnomalyEndDate,
            totalImpactUsd: a.Impact?.TotalImpact,
            expectedUsd: a.Impact?.TotalExpectedSpend,
            actualUsd: a.Impact?.TotalActualSpend,
            rootCauses: (a.RootCauses ?? []).map((r) => ({
              service: r.Service,
              account: r.LinkedAccount,
              region: r.Region,
              usageType: r.UsageType,
            })),
            feedback: a.Feedback,
          })),
        };
      },
    },
  ];
}
