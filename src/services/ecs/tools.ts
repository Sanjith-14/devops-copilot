import {
  ECSClient,
  ListClustersCommand,
  DescribeClustersCommand,
  ListServicesCommand,
  DescribeServicesCommand,
  ListTasksCommand,
  DescribeTasksCommand,
  type Service,
  type Task,
} from "@aws-sdk/client-ecs";
import { z } from "zod";
import type { ToolDefinition, ToolContext } from "../../core/types.js";
import type { AwsClientFactory } from "../../core/aws-client.js";
import { mapLimited } from "../../core/helpers.js";

const shortArn = (arn?: string) => arn?.split("/").pop();

/** Health verdict for one ECS service. Pure — unit-tested. */
export function serviceHealth(s: Service) {
  const primary = s.deployments?.find((d) => d.status === "PRIMARY");
  const problems: string[] = [];
  if ((s.runningCount ?? 0) < (s.desiredCount ?? 0)) problems.push(`running ${s.runningCount}/${s.desiredCount} tasks`);
  if (primary?.rolloutState === "FAILED") problems.push(`deployment FAILED: ${primary.rolloutStateReason ?? ""}`.trim());
  if ((s.deployments?.length ?? 0) > 1) problems.push(`${s.deployments!.length} deployments active (rollout in progress or stuck)`);
  if ((primary?.failedTasks ?? 0) > 0) problems.push(`${primary!.failedTasks} task(s) failed to start in current deployment`);
  return {
    name: s.serviceName,
    status: s.status,
    healthy: problems.length === 0,
    desired: s.desiredCount,
    running: s.runningCount,
    pending: s.pendingCount,
    launchType: s.launchType ?? s.capacityProviderStrategy?.map((c) => c.capacityProvider).join(","),
    taskDefinition: shortArn(s.taskDefinition),
    rollout: primary?.rolloutState,
    problems,
    recentEvents: (s.events ?? []).slice(0, 3).map((e) => `${e.createdAt instanceof Date ? e.createdAt.toISOString() : e.createdAt} ${e.message}`),
  };
}

/** Why tasks stopped: task + per-container reasons and exit codes. Pure. */
export const stoppedTaskSummary = (t: Task) => ({
  task: shortArn(t.taskArn),
  stoppedAt: t.stoppedAt instanceof Date ? t.stoppedAt.toISOString() : t.stoppedAt,
  stopCode: t.stopCode,
  reason: t.stoppedReason,
  containers: (t.containers ?? [])
    .filter((c) => c.exitCode !== 0 || c.reason)
    .map((c) => ({ name: c.name, exitCode: c.exitCode, reason: c.reason })),
});

export function buildEcsTools(factory: AwsClientFactory): ToolDefinition[] {
  const ecs = (ctx: ToolContext) => factory.getClient(ECSClient, ctx.accountId, ctx.region).client;

  return [
    {
      name: "list_clusters",
      description: "List ECS clusters with status, running/pending task counts, active services and container instances.",
      risk: "read",
      inputSchema: {},
      handler: async (_args, ctx) => {
        const arns: string[] = [];
        let nextToken: string | undefined;
        do {
          const r = await ecs(ctx).send(new ListClustersCommand({ nextToken }));
          arns.push(...(r.clusterArns ?? []));
          nextToken = r.nextToken;
        } while (nextToken);
        const clusters = [];
        for (let i = 0; i < arns.length; i += 100) {
          const r = await ecs(ctx).send(new DescribeClustersCommand({ clusters: arns.slice(i, i + 100) }));
          clusters.push(...(r.clusters ?? []));
        }
        return {
          count: clusters.length,
          clusters: clusters.map((c) => ({
            name: c.clusterName,
            status: c.status,
            runningTasks: c.runningTasksCount,
            pendingTasks: c.pendingTasksCount,
            services: c.activeServicesCount,
            containerInstances: c.registeredContainerInstancesCount,
            capacityProviders: c.capacityProviders,
          })),
        };
      },
    },
    {
      name: "service_health",
      description:
        "Health of ECS services in a cluster: desired vs running tasks, deployment rollout state, failed task " +
        "starts, recent service events, and — for unhealthy services — WHY tasks stopped (stop reason, container " +
        "exit codes). Answers 'is my service up?' and 'why does it keep restarting?'.",
      risk: "read",
      inputSchema: {
        cluster: z.string().max(255).describe("Cluster name or ARN"),
        service: z.string().max(255).optional().describe("Only this service (default: all services in the cluster)"),
      },
      handler: async (args, ctx) => {
        const cluster = args.cluster as string;
        let names: string[];
        if (args.service) names = [args.service as string];
        else {
          names = [];
          let nextToken: string | undefined;
          do {
            const r = await ecs(ctx).send(new ListServicesCommand({ cluster, nextToken, maxResults: 100 }));
            names.push(...(r.serviceArns ?? []));
            nextToken = r.nextToken;
          } while (nextToken && names.length < 200);
        }

        const services: Service[] = [];
        for (let i = 0; i < names.length; i += 10) {
          const r = await ecs(ctx).send(new DescribeServicesCommand({ cluster, services: names.slice(i, i + 10) }));
          services.push(...(r.services ?? []));
        }
        const health = services.map(serviceHealth);

        // For unhealthy services, explain recent task stops (max 10 services, 5 tasks each).
        const unhealthy = health.filter((h) => !h.healthy).slice(0, 10);
        const stops = await mapLimited(unhealthy, 3, async (h) => {
          const list = await ecs(ctx).send(new ListTasksCommand({ cluster, serviceName: h.name, desiredStatus: "STOPPED", maxResults: 5 }));
          if (!list.taskArns?.length) return { service: h.name, stoppedTasks: [] };
          const tasks = await ecs(ctx).send(new DescribeTasksCommand({ cluster, tasks: list.taskArns }));
          return { service: h.name, stoppedTasks: (tasks.tasks ?? []).map(stoppedTaskSummary) };
        });
        const stopsByService = new Map(stops.map((s) => [s.service, s.stoppedTasks]));

        return {
          cluster,
          services: health.length,
          unhealthy: unhealthy.length,
          results: health
            .sort((a, b) => Number(a.healthy) - Number(b.healthy))
            .map((h) => (h.healthy ? h : { ...h, recentStoppedTasks: stopsByService.get(h.name) })),
        };
      },
    },
  ];
}
