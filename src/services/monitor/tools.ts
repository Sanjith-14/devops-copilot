import { AutoScalingClient, DescribeAutoScalingGroupsCommand } from "@aws-sdk/client-auto-scaling";
import { CloudWatchClient, DescribeAlarmsCommand } from "@aws-sdk/client-cloudwatch";
import { z } from "zod";
import type { ToolDefinition, ToolContext } from "../../core/types.js";
import type { AwsClientFactory } from "../../core/aws-client.js";

/**
 * Monitor module: instead of returning raw resources, these tools EVALUATE
 * state and emit human-readable text alerts with a severity, so the LLM can
 * read them and decide what to do next (notify, investigate, escalate).
 *
 * Alert contract:
 *   severity: "critical" | "warning" | "info"
 *   message:  one line of plain text, self-contained (no ids the LLM must resolve)
 * Overall status = worst severity found ("OK" when no alerts).
 */
export interface Alert {
  severity: "critical" | "warning" | "info";
  source: string;
  message: string;
}

function overallStatus(alerts: Alert[]): "OK" | "INFO" | "WARNING" | "CRITICAL" {
  if (alerts.some((a) => a.severity === "critical")) return "CRITICAL";
  if (alerts.some((a) => a.severity === "warning")) return "WARNING";
  if (alerts.length > 0) return "INFO";
  return "OK";
}

function summarize(alerts: Alert[]): string {
  if (alerts.length === 0) return "All checks passed — nothing needs attention.";
  return alerts.map((a) => `[${a.severity.toUpperCase()}] ${a.message}`).join("\n");
}

export function buildMonitorTools(factory: AwsClientFactory): ToolDefinition[] {
  const asg = (ctx: ToolContext) => factory.getClient(AutoScalingClient, ctx.accountId, ctx.region).client;
  const cw = (ctx: ToolContext) => factory.getClient(CloudWatchClient, ctx.accountId, ctx.region).client;

  /** Check 1: ASG instance health — detached / not-InService instances, capacity gaps. */
  async function checkAsgInstances(ctx: ToolContext, envTag?: string, nameContains?: string): Promise<Alert[]> {
    const alerts: Alert[] = [];
    const res = await asg(ctx).send(new DescribeAutoScalingGroupsCommand({}));
    let groups = res.AutoScalingGroups ?? [];

    if (envTag) {
      groups = groups.filter((g) =>
        (g.Tags ?? []).some((t) => t.Key?.toLowerCase() === "environment" && t.Value === envTag),
      );
    }
    if (nameContains) {
      groups = groups.filter((g) => g.AutoScalingGroupName?.includes(nameContains));
    }

    for (const g of groups) {
      const name = g.AutoScalingGroupName ?? "?";
      const instances = g.Instances ?? [];

      for (const i of instances) {
        const state = i.LifecycleState ?? "?";
        const healthy = i.HealthStatus === "Healthy";
        if (state.startsWith("Detach") || state.startsWith("Terminating")) {
          alerts.push({
            severity: "critical",
            source: `asg/${name}`,
            message: `ASG "${name}": instance ${i.InstanceId} is ${state} in ${i.AvailabilityZone} (health: ${i.HealthStatus}) — the group is losing capacity.`,
          });
        } else if (state !== "InService") {
          alerts.push({
            severity: "warning",
            source: `asg/${name}`,
            message: `ASG "${name}": instance ${i.InstanceId} is ${state} (not InService) in ${i.AvailabilityZone}.`,
          });
        } else if (!healthy) {
          alerts.push({
            severity: "critical",
            source: `asg/${name}`,
            message: `ASG "${name}": instance ${i.InstanceId} is InService but reports health "${i.HealthStatus}".`,
          });
        }
      }

      const inService = instances.filter((i) => i.LifecycleState === "InService").length;
      const desired = g.DesiredCapacity ?? 0;
      if (inService < desired) {
        alerts.push({
          severity: inService === 0 && desired > 0 ? "critical" : "warning",
          source: `asg/${name}`,
          message: `ASG "${name}" is under capacity: ${inService}/${desired} instances InService (min=${g.MinSize}, max=${g.MaxSize}).`,
        });
      }
      if ((g.SuspendedProcesses ?? []).length > 0) {
        const procs = (g.SuspendedProcesses ?? []).map((p) => p.ProcessName).join(", ");
        alerts.push({
          severity: "info",
          source: `asg/${name}`,
          message: `ASG "${name}" has suspended processes (${procs}) — scaling may be intentionally paused.`,
        });
      }
    }
    return alerts;
  }

  /** Check 2: CloudWatch alarms currently firing or lacking data. */
  async function checkAlarms(ctx: ToolContext, includeInsufficientData: boolean): Promise<Alert[]> {
    const alerts: Alert[] = [];
    const client = cw(ctx);

    const firing = await client.send(new DescribeAlarmsCommand({ StateValue: "ALARM", MaxRecords: 100 }));
    for (const a of firing.MetricAlarms ?? []) {
      alerts.push({
        severity: "critical",
        source: `alarm/${a.AlarmName}`,
        message: `Alarm "${a.AlarmName}" is in ALARM since ${a.StateUpdatedTimestamp?.toISOString()} (metric ${a.Namespace}/${a.MetricName}): ${a.StateReason}`,
      });
    }
    for (const a of firing.CompositeAlarms ?? []) {
      alerts.push({
        severity: "critical",
        source: `alarm/${a.AlarmName}`,
        message: `Composite alarm "${a.AlarmName}" is in ALARM: ${a.StateReason}`,
      });
    }

    if (includeInsufficientData) {
      const nodata = await client.send(new DescribeAlarmsCommand({ StateValue: "INSUFFICIENT_DATA", MaxRecords: 100 }));
      for (const a of nodata.MetricAlarms ?? []) {
        alerts.push({
          severity: "info",
          source: `alarm/${a.AlarmName}`,
          message: `Alarm "${a.AlarmName}" has INSUFFICIENT_DATA (metric ${a.Namespace}/${a.MetricName}) — it may be watching a dead resource.`,
        });
      }
    }
    return alerts;
  }

  return [
    {
      name: "run_checks",
      description:
        "Run every health check (ASG instance health/detachment, capacity gaps, firing CloudWatch alarms) and return text alerts with severities plus an overall OK/WARNING/CRITICAL status. Designed for 'is anything wrong right now?' triage — read the alerts and decide what to investigate.",
      risk: "read",
      inputSchema: {
        envTag: z
          .string()
          .max(100)
          .optional()
          .describe("Only check ASGs whose 'Environment' tag equals this value, e.g. 'prod'."),
        includeInsufficientData: z
          .boolean()
          .optional()
          .describe("Also report alarms in INSUFFICIENT_DATA state as info alerts (default false)."),
      },
      handler: async (args, ctx) => {
        const alerts: Alert[] = [];
        const failures: string[] = [];

        const checks: [string, Promise<Alert[]>][] = [
          ["asg_instances", checkAsgInstances(ctx, args.envTag as string | undefined)],
          ["cloudwatch_alarms", checkAlarms(ctx, (args.includeInsufficientData as boolean | undefined) ?? false)],
        ];
        for (const [name, p] of checks) {
          try {
            alerts.push(...(await p));
          } catch (err) {
            failures.push(`check "${name}" could not run: ${String(err)}`);
          }
        }

        return {
          status: overallStatus(alerts),
          alertCount: alerts.length,
          summary: summarize(alerts),
          alerts,
          checkFailures: failures.length > 0 ? failures : undefined,
        };
      },
    },
    {
      name: "check_asg_instances",
      description:
        "Detect Auto Scaling problems: detached/terminating instances, instances not InService, unhealthy instances, and groups running under desired capacity. Returns text alerts with severities.",
      risk: "read",
      inputSchema: {
        envTag: z
          .string()
          .max(100)
          .optional()
          .describe("Only check ASGs whose 'Environment' tag equals this value, e.g. 'prod'."),
        nameContains: z.string().max(200).optional().describe("Only check ASGs whose name contains this substring."),
      },
      handler: async (args, ctx) => {
        const alerts = await checkAsgInstances(
          ctx,
          args.envTag as string | undefined,
          args.nameContains as string | undefined,
        );
        return { status: overallStatus(alerts), alertCount: alerts.length, summary: summarize(alerts), alerts };
      },
    },
    {
      name: "check_alarms",
      description:
        "Report CloudWatch alarms currently firing (ALARM state) as critical text alerts, optionally including INSUFFICIENT_DATA alarms as info.",
      risk: "read",
      inputSchema: {
        includeInsufficientData: z
          .boolean()
          .optional()
          .describe("Also report INSUFFICIENT_DATA alarms as info alerts (default false)."),
      },
      handler: async (args, ctx) => {
        const alerts = await checkAlarms(ctx, (args.includeInsufficientData as boolean | undefined) ?? false);
        return { status: overallStatus(alerts), alertCount: alerts.length, summary: summarize(alerts), alerts };
      },
    },
  ];
}
