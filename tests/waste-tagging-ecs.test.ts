import { describe, it, expect } from "vitest";
import createCostModule from "../src/services/cost/index.js";
import createTaggingModule from "../src/services/tagging/index.js";
import createEcsModule from "../src/services/ecs/index.js";
import { addressWaste, snapshotWaste, volumeWaste } from "../src/services/cost/waste.js";
import { missingTags, resourceType } from "../src/services/tagging/tools.js";
import { serviceHealth, stoppedTaskSummary } from "../src/services/ecs/tools.js";
import { fakeFactory, ctx } from "./fake-aws.js";

const now = Date.parse("2026-10-15T00:00:00Z");
const daysAgo = (d: number) => new Date(now - d * 86_400_000);

describe("waste helpers", () => {
  it("prices unattached volumes, idle EIPs and old snapshots", () => {
    expect(volumeWaste([{ VolumeId: "vol-1", State: "available", VolumeType: "gp3", Size: 100, CreateTime: daysAgo(40) }, { VolumeId: "vol-2", State: "in-use" }], now)).toEqual([
      { resource: "vol-1", why: "unattached gp3 volume (100 GB)", ageDays: 40, estMonthlyUSD: 8 },
    ]);
    expect(addressWaste([{ PublicIp: "3.3.3.3" }, { PublicIp: "4.4.4.4", AssociationId: "a" }])).toHaveLength(1);
    expect(snapshotWaste([{ SnapshotId: "snap-1", StartTime: daysAgo(400), VolumeSize: 50 }, { SnapshotId: "snap-2", StartTime: daysAgo(5) }], 180, now)).toMatchObject([
      { resource: "snap-1", estMonthlyUSD: 2.5 },
    ]);
  });

  it("find_waste returns partial results when EC2 is denied", async () => {
    const denied = new Error("UnauthorizedOperation: You are not authorized to perform this operation.");
    const { factory } = fakeFactory({
      DescribeVolumesCommand: denied,
      DescribeAddressesCommand: denied,
      DescribeSnapshotsCommand: denied,
      DescribeDBInstancesCommand: { DBInstances: [{ DBInstanceIdentifier: "idle-db", DBInstanceStatus: "available", DBInstanceClass: "db.t3.micro" }] },
      GetMetricStatisticsCommand: (i: { MetricName: string }) => ({
        Datapoints: [{ Average: 1.2, Maximum: 0, Sum: i.MetricName === "Invocations" ? 0 : undefined }],
      }),
      DescribeLoadBalancersCommand: { LoadBalancers: [{ LoadBalancerName: "orphan", LoadBalancerArn: "arn:lb/orphan", Type: "application" }] },
      DescribeTargetGroupsCommand: { TargetGroups: [] },
      ListFunctionsCommand: { Functions: [{ FunctionName: "old-fn", LastModified: "2024-01-01T00:00:00.000+0000" }] },
    });
    const waste = createCostModule(factory).tools.find((t) => t.name === "find_waste")!;
    const out = (await waste.handler({}, ctx)) as any;
    expect(out.summary.volumes.skipped).toMatch(/no permission/);
    expect(out.summary.idleRds.count).toBe(1);
    expect(out.summary.emptyLoadBalancers).toMatchObject({ count: 1, estMonthlyUSD: 16.4 });
    expect(out.summary.unusedLambdas.count).toBe(1);
    expect(out.estimatedMonthlyWasteUSD).toBe(16.4);
  });
});

describe("tagging", () => {
  it("derives resource types and missing tags", () => {
    expect(resourceType("arn:aws:ec2:ap-south-1:1:instance/i-1")).toBe("ec2:instance");
    expect(resourceType("arn:aws:s3:::my-bucket")).toBe("s3");
    expect(resourceType("arn:aws:lambda:ap-south-1:1:function:fn")).toBe("lambda:function");
    expect(missingTags({ Tags: [{ Key: "owner", Value: "me" }, { Key: "Environment", Value: " " }] }, ["Owner", "Environment"])).toEqual(["Environment"]);
  });

  it("find_untagged computes compliance", async () => {
    const { factory } = fakeFactory({
      GetResourcesCommand: {
        ResourceTagMappingList: [
          { ResourceARN: "arn:aws:s3:::a", Tags: [{ Key: "Owner", Value: "x" }, { Key: "Environment", Value: "dev" }] },
          { ResourceARN: "arn:aws:s3:::b", Tags: [] },
          { ResourceARN: "arn:aws:ec2:r:1:instance/i-1", Tags: [{ Key: "Owner", Value: "x" }] },
        ],
      },
    });
    const out = (await createTaggingModule(factory).tools[0].handler({}, ctx)) as any;
    expect(out).toMatchObject({ resourcesScanned: 3, noncompliant: 2, compliancePct: 33 });
    expect(out.byType).toEqual([{ name: "s3", count: 1 }, { name: "ec2:instance", count: 1 }]);
  });
});

describe("ecs", () => {
  it("judges service health", () => {
    expect(serviceHealth({ serviceName: "ok", desiredCount: 2, runningCount: 2, deployments: [{ status: "PRIMARY", rolloutState: "COMPLETED" }] }).healthy).toBe(true);
    const bad = serviceHealth({
      serviceName: "api",
      desiredCount: 3,
      runningCount: 1,
      deployments: [{ status: "PRIMARY", rolloutState: "FAILED", rolloutStateReason: "circuit breaker", failedTasks: 4 }, { status: "ACTIVE" }],
    });
    expect(bad.healthy).toBe(false);
    expect(bad.problems).toEqual([
      "running 1/3 tasks",
      "deployment FAILED: circuit breaker",
      "2 deployments active (rollout in progress or stuck)",
      "4 task(s) failed to start in current deployment",
    ]);
  });

  it("explains stopped tasks for unhealthy services", async () => {
    const { factory } = fakeFactory({
      ListServicesCommand: { serviceArns: ["arn:svc/api", "arn:svc/web"] },
      DescribeServicesCommand: {
        services: [
          { serviceName: "api", desiredCount: 2, runningCount: 0, deployments: [{ status: "PRIMARY" }] },
          { serviceName: "web", desiredCount: 1, runningCount: 1, deployments: [{ status: "PRIMARY" }] },
        ],
      },
      ListTasksCommand: { taskArns: ["arn:task/t1"] },
      DescribeTasksCommand: {
        tasks: [{ taskArn: "arn:task/t1", stopCode: "EssentialContainerExited", stoppedReason: "Essential container in task exited", containers: [{ name: "app", exitCode: 137, reason: "OutOfMemoryError" }, { name: "sidecar", exitCode: 0 }] }],
      },
    });
    const out = (await createEcsModule(factory).tools[1].handler({ cluster: "prod" }, ctx)) as any;
    expect(out).toMatchObject({ services: 2, unhealthy: 1 });
    expect(out.results[0].name).toBe("api");
    expect(out.results[0].recentStoppedTasks[0].containers).toEqual([{ name: "app", exitCode: 137, reason: "OutOfMemoryError" }]);
    expect(stoppedTaskSummary({ taskArn: "a/b" }).task).toBe("b");
  });
});
