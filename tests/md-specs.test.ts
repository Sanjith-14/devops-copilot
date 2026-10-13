import { describe, it, expect } from "vitest";
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { parseToolMarkdown, parseModuleMarkdown, type MdToolSpec } from "../src/core/md-tools.js";
import { loadSdkCommand, shapeOutput } from "../src/core/aws-ops.js";

const SERVICES = join(__dirname, "..", "src", "services");

/** Every *.tool.md shipped in the repo. */
const specs: { file: string; spec: MdToolSpec }[] = [];
for (const mod of readdirSync(SERVICES)) {
  const dir = join(SERVICES, mod);
  for (const f of readdirSync(dir).filter((f) => f.endsWith(".tool.md"))) {
    specs.push({ file: `${mod}/${f}`, spec: parseToolMarkdown(readFileSync(join(dir, f), "utf8"), f) });
  }
}
const byName = (n: string) => specs.find((s) => s.spec.name === n)!.spec;

describe("shipped markdown tool specs", () => {
  it("finds the ec2 and elb tools", () => {
    expect(specs.length).toBeGreaterThanOrEqual(11);
  });

  it.each(specs.map((s) => [s.file, s.spec] as const))("%s: read-only, valid SDK op, valid JMESPath", async (_f, spec) => {
    expect(spec.risk).toBe("read");
    await loadSdkCommand(spec.service, spec.operation);
    if (spec.output) expect(() => shapeOutput({}, { output: spec.output })).not.toThrow();
  });

  it("module.md (for markdown-only modules) parses and guards its health op", () => {
    const meta = parseModuleMarkdown(
      "---\nhealth: { service: ecs, operation: ListClusters }\n---\nAmazon ECS clusters and services.\n",
    );
    expect(meta).toEqual({
      description: "Amazon ECS clusters and services.",
      health: { service: "ecs", operation: "ListClusters" },
    });
    expect(() => parseModuleMarkdown("---\nhealth: { service: ecs, operation: DeleteCluster }\n---\nx\n")).toThrow(
      /not read-only/,
    );
  });
});

describe("projections on sample AWS responses", () => {
  it("list_instances flattens reservations and pulls the Name tag", () => {
    const out = shapeOutput(
      {
        Reservations: [
          {
            Instances: [
              {
                InstanceId: "i-1",
                InstanceType: "t3.micro",
                State: { Name: "running" },
                Tags: [{ Key: "env", Value: "dev" }, { Key: "Name", Value: "api-1" }],
                VpcId: "vpc-1",
                SubnetId: "subnet-1",
                Placement: { AvailabilityZone: "ap-south-1a" },
                SecurityGroups: [{ GroupId: "sg-1", GroupName: "web" }],
              },
            ],
          },
          { Instances: [{ InstanceId: "i-2", State: { Name: "stopped" } }] },
        ],
      },
      { output: byName("list_instances").output },
    );
    expect(out.count).toBe(2);
    expect((out.items as any[])[0]).toMatchObject({ id: "i-1", name: "api-1", state: "running", securityGroups: ["sg-1"] });
    expect((out.items as any[])[1]).toMatchObject({ id: "i-2", name: null });
  });

  it("describe_route_tables marks main tables and resolves route targets", () => {
    const out = shapeOutput(
      {
        RouteTables: [
          {
            RouteTableId: "rtb-1",
            VpcId: "vpc-1",
            Associations: [{ Main: true }],
            Routes: [
              { DestinationCidrBlock: "10.0.0.0/16", GatewayId: "local", State: "active" },
              { DestinationCidrBlock: "0.0.0.0/0", GatewayId: "igw-1", State: "active" },
            ],
          },
          {
            RouteTableId: "rtb-2",
            VpcId: "vpc-1",
            Associations: [{ Main: false, SubnetId: "subnet-2" }],
            Routes: [{ DestinationCidrBlock: "0.0.0.0/0", NatGatewayId: "nat-1", State: "blackhole" }],
          },
        ],
      },
      { output: byName("describe_route_tables").output },
    );
    const [main, priv] = out.items as any[];
    expect(main).toMatchObject({ id: "rtb-1", main: true, subnets: [] });
    expect(main.routes[1]).toEqual({ destination: "0.0.0.0/0", target: "igw-1", state: "active" });
    expect(priv).toMatchObject({ id: "rtb-2", main: false, subnets: ["subnet-2"] });
    expect(priv.routes[0]).toEqual({ destination: "0.0.0.0/0", target: "nat-1", state: "blackhole" });
  });

  it("get_target_health flattens target + health", () => {
    const out = shapeOutput(
      {
        TargetHealthDescriptions: [
          { Target: { Id: "i-1", Port: 80 }, TargetHealth: { State: "unhealthy", Reason: "Target.Timeout" } },
        ],
      },
      { output: byName("get_target_health").output },
    );
    expect((out.items as any[])[0]).toEqual({
      target: "i-1",
      port: 80,
      az: null,
      state: "unhealthy",
      reason: "Target.Timeout",
      detail: null,
    });
  });
});
