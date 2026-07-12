import {
  AutoScalingClient,
  DescribeAutoScalingGroupsCommand,
  DescribeAutoScalingInstancesCommand,
  DescribePoliciesCommand,
  DescribeScalingActivitiesCommand,
} from "@aws-sdk/client-auto-scaling";
import { z } from "zod";
import type { ToolDefinition, ToolContext } from "../../core/types.js";
import type { AwsClientFactory } from "../../core/aws-client.js";

/**
 * Auto Scaling tools — read-only by design. Capacity changes (mutate) are
 * intentionally not exposed; this module only inspects groups, instances,
 * policies, and scaling history.
 */
export function buildAsgTools(factory: AwsClientFactory): ToolDefinition[] {
  const asg = (ctx: ToolContext) => factory.getClient(AutoScalingClient, ctx.accountId, ctx.region).client;

  return [
    {
      name: "list_groups",
      description:
        "List Auto Scaling groups with capacity settings (min/max/desired), instance counts, health-check type, and availability zones.",
      risk: "read",
      inputSchema: {
        names: z.array(z.string()).optional().describe("Filter to specific group names. Omit for all groups."),
        limit: z.number().int().min(1).max(100).optional().describe("Max groups to return (default 50)"),
      },
      handler: async (args, ctx) => {
        const res = await asg(ctx).send(
          new DescribeAutoScalingGroupsCommand({
            AutoScalingGroupNames: args.names as string[] | undefined,
            MaxRecords: (args.limit as number | undefined) ?? 50,
          }),
        );
        const groups = res.AutoScalingGroups ?? [];
        return {
          count: groups.length,
          truncated: Boolean(res.NextToken),
          groups: groups.map((g) => ({
            name: g.AutoScalingGroupName,
            min: g.MinSize,
            max: g.MaxSize,
            desired: g.DesiredCapacity,
            instanceCount: g.Instances?.length ?? 0,
            healthCheckType: g.HealthCheckType,
            availabilityZones: g.AvailabilityZones,
            launchTemplate: g.LaunchTemplate?.LaunchTemplateName ?? g.LaunchConfigurationName,
            created: g.CreatedTime,
          })),
        };
      },
    },
    {
      name: "describe_group",
      description:
        "Full detail for one Auto Scaling group: capacity, instances with lifecycle/health state, load balancer targets, suspended processes, and tags.",
      risk: "read",
      inputSchema: { name: z.string().describe("Auto Scaling group name") },
      handler: async (args, ctx) => {
        const res = await asg(ctx).send(
          new DescribeAutoScalingGroupsCommand({ AutoScalingGroupNames: [args.name as string] }),
        );
        const g = res.AutoScalingGroups?.[0];
        if (!g) return { name: args.name, found: false };
        return {
          name: g.AutoScalingGroupName,
          found: true,
          min: g.MinSize,
          max: g.MaxSize,
          desired: g.DesiredCapacity,
          healthCheckType: g.HealthCheckType,
          healthCheckGracePeriodSeconds: g.HealthCheckGracePeriod,
          availabilityZones: g.AvailabilityZones,
          launchTemplate: g.LaunchTemplate?.LaunchTemplateName ?? g.LaunchConfigurationName,
          targetGroupArns: g.TargetGroupARNs,
          suspendedProcesses: (g.SuspendedProcesses ?? []).map((p) => p.ProcessName),
          instances: (g.Instances ?? []).map((i) => ({
            instanceId: i.InstanceId,
            availabilityZone: i.AvailabilityZone,
            lifecycleState: i.LifecycleState,
            healthStatus: i.HealthStatus,
            instanceType: i.InstanceType,
          })),
          tags: (g.Tags ?? []).map((t) => ({ key: t.Key, value: t.Value })),
          created: g.CreatedTime,
        };
      },
    },
    {
      name: "list_instances",
      description:
        "List instances managed by Auto Scaling across all groups, with lifecycle state, health status, and owning group.",
      risk: "read",
      inputSchema: {
        instanceIds: z.array(z.string()).optional().describe("Filter to specific EC2 instance ids. Omit for all."),
        limit: z.number().int().min(1).max(50).optional().describe("Max instances to return (default 50)"),
      },
      handler: async (args, ctx) => {
        const res = await asg(ctx).send(
          new DescribeAutoScalingInstancesCommand({
            InstanceIds: args.instanceIds as string[] | undefined,
            MaxRecords: (args.limit as number | undefined) ?? 50,
          }),
        );
        const instances = res.AutoScalingInstances ?? [];
        return {
          count: instances.length,
          truncated: Boolean(res.NextToken),
          instances: instances.map((i) => ({
            instanceId: i.InstanceId,
            group: i.AutoScalingGroupName,
            availabilityZone: i.AvailabilityZone,
            lifecycleState: i.LifecycleState,
            healthStatus: i.HealthStatus,
            instanceType: i.InstanceType,
            launchTemplate: i.LaunchTemplate?.LaunchTemplateName ?? i.LaunchConfigurationName,
          })),
        };
      },
    },
    {
      name: "list_scaling_policies",
      description:
        "List scaling policies for a group (or all groups): policy type, metric/target for target-tracking, adjustments for step/simple scaling.",
      risk: "read",
      inputSchema: {
        group: z.string().optional().describe("Auto Scaling group name. Omit for policies across all groups."),
      },
      handler: async (args, ctx) => {
        const res = await asg(ctx).send(
          new DescribePoliciesCommand({ AutoScalingGroupName: args.group as string | undefined }),
        );
        const policies = res.ScalingPolicies ?? [];
        return {
          count: policies.length,
          policies: policies.map((p) => ({
            name: p.PolicyName,
            group: p.AutoScalingGroupName,
            type: p.PolicyType,
            enabled: p.Enabled,
            adjustmentType: p.AdjustmentType,
            scalingAdjustment: p.ScalingAdjustment,
            targetTracking: p.TargetTrackingConfiguration
              ? {
                  metric: p.TargetTrackingConfiguration.PredefinedMetricSpecification?.PredefinedMetricType,
                  targetValue: p.TargetTrackingConfiguration.TargetValue,
                }
              : undefined,
            alarms: (p.Alarms ?? []).map((a) => a.AlarmName),
          })),
        };
      },
    },
    {
      name: "list_scaling_activities",
      description:
        "Recent scaling activity history for a group (or all groups): what scaled, when, why (cause), and whether it succeeded.",
      risk: "read",
      inputSchema: {
        group: z.string().optional().describe("Auto Scaling group name. Omit for activity across all groups."),
        limit: z.number().int().min(1).max(100).optional().describe("Max activities to return (default 20)"),
      },
      handler: async (args, ctx) => {
        const res = await asg(ctx).send(
          new DescribeScalingActivitiesCommand({
            AutoScalingGroupName: args.group as string | undefined,
            MaxRecords: (args.limit as number | undefined) ?? 20,
          }),
        );
        const activities = res.Activities ?? [];
        return {
          count: activities.length,
          activities: activities.map((a) => ({
            group: a.AutoScalingGroupName,
            description: a.Description,
            cause: a.Cause,
            status: a.StatusCode,
            statusMessage: a.StatusMessage,
            start: a.StartTime,
            end: a.EndTime,
          })),
        };
      },
    },
  ];
}
