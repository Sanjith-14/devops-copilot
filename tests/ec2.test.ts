import { describe, it, expect } from "vitest";
import { join } from "node:path";
import createEc2Module from "../src/services/ec2/index.js";
import { loadMarkdownTools } from "../src/core/md-tools.js";
import {
  defaultRoute,
  describeRoute,
  exposureVerdict,
  findWorldOpenRules,
  routeTableForSubnet,
  summarizeRules,
} from "../src/services/ec2/network.js";
import { fakeFactory, ctx } from "./fake-aws.js";

const MAIN_RT = {
  RouteTableId: "rtb-main",
  Associations: [{ Main: true }],
  Routes: [
    { DestinationCidrBlock: "10.0.0.0/16", GatewayId: "local", State: "active" },
    { DestinationCidrBlock: "0.0.0.0/0", GatewayId: "igw-1", State: "active" },
  ],
};
const PRIVATE_RT = {
  RouteTableId: "rtb-priv",
  Associations: [{ Main: false, SubnetId: "subnet-priv" }],
  Routes: [{ DestinationCidrBlock: "0.0.0.0/0", NatGatewayId: "nat-1", State: "active" }],
};
const SSH_OPEN = {
  GroupId: "sg-ssh",
  GroupName: "ssh-anywhere",
  IpPermissions: [
    { IpProtocol: "tcp", FromPort: 22, ToPort: 22, IpRanges: [{ CidrIp: "0.0.0.0/0" }] },
    { IpProtocol: "tcp", FromPort: 443, ToPort: 443, IpRanges: [{ CidrIp: "0.0.0.0/0" }] },
    { IpProtocol: "tcp", FromPort: 8080, ToPort: 8080, UserIdGroupPairs: [{ GroupId: "sg-lb" }] },
  ],
  IpPermissionsEgress: [{ IpProtocol: "-1", IpRanges: [{ CidrIp: "0.0.0.0/0" }] }],
};

describe("network helpers", () => {
  it("classifies route targets", () => {
    expect(describeRoute({ DestinationCidrBlock: "0.0.0.0/0", NatGatewayId: "nat-9" }).kind).toBe("nat-gateway");
    expect(describeRoute({ DestinationCidrBlock: "10.1.0.0/16", TransitGatewayId: "tgw-1" }).kind).toBe("transit-gateway");
    expect(describeRoute({ DestinationCidrBlock: "10.0.0.0/16", GatewayId: "local" }).kind).toBe("local");
    expect(describeRoute({ DestinationPrefixListId: "pl-1", GatewayId: "vpce-1" }).kind).toBe("vpc-endpoint");
  });

  it("falls back to the main route table for subnets without an explicit association", () => {
    expect(routeTableForSubnet([MAIN_RT, PRIVATE_RT], "subnet-priv")).toMatchObject({
      table: { RouteTableId: "rtb-priv" },
      association: "explicit",
    });
    expect(routeTableForSubnet([MAIN_RT, PRIVATE_RT], "subnet-other")).toMatchObject({
      table: { RouteTableId: "rtb-main" },
      association: "main (implicit)",
    });
  });

  it("ignores blackhole default routes", () => {
    expect(defaultRoute({ Routes: [{ DestinationCidrBlock: "0.0.0.0/0", NatGatewayId: "nat-x", State: "blackhole" }] })).toBeUndefined();
    expect(defaultRoute(MAIN_RT)?.target).toBe("igw-1");
  });

  it("summarizes rules one line per peer", () => {
    expect(summarizeRules(SSH_OPEN.IpPermissions, "from")).toEqual([
      "tcp 22 from 0.0.0.0/0",
      "tcp 443 from 0.0.0.0/0",
      "tcp 8080 from sg-lb",
    ]);
    expect(summarizeRules(SSH_OPEN.IpPermissionsEgress, "to")).toEqual(["all traffic to 0.0.0.0/0"]);
  });

  it("grades world-open rules by severity", () => {
    const f = findWorldOpenRules([
      ...SSH_OPEN.IpPermissions,
      { IpProtocol: "-1", Ipv6Ranges: [{ CidrIpv6: "::/0" }] },
      { IpProtocol: "tcp", FromPort: 3000, ToPort: 3500, IpRanges: [{ CidrIp: "0.0.0.0/0" }] },
      { IpProtocol: "tcp", FromPort: 3300, ToPort: 3400, IpRanges: [{ CidrIp: "0.0.0.0/0" }] },
      { IpProtocol: "tcp", FromPort: 5432, ToPort: 5432, IpRanges: [{ CidrIp: "10.0.0.0/8" }] },
    ]);
    expect(f.map((x) => [x.rule, x.severity])).toEqual([
      ["tcp 22 from 0.0.0.0/0", "high"],
      ["tcp 443 from 0.0.0.0/0", "info"],
      ["all traffic from ::/0", "high"],
      ["tcp 3000-3500 from 0.0.0.0/0", "high"], // contains MySQL 3306 + RDP 3389
      ["tcp 3300-3400 from 0.0.0.0/0", "high"],
    ]);
    expect(f[3].reason).toMatch(/MySQL \(3306\).*RDP \(3389\)/);
  });

  it("needs public IP + IGW route + open SG for inbound exposure", () => {
    const open = findWorldOpenRules(SSH_OPEN.IpPermissions);
    const igw = defaultRoute(MAIN_RT);
    const nat = defaultRoute(PRIVATE_RT);
    expect(exposureVerdict({ publicIp: "1.2.3.4", defaultRoute: igw, worldOpenInbound: open }).inboundFromInternet).toBe(true);
    expect(exposureVerdict({ defaultRoute: igw, worldOpenInbound: open })).toMatchObject({
      inboundFromInternet: false,
      outboundToInternet: "none — route to igw-1 but no public IP",
    });
    const priv = exposureVerdict({ publicIp: "1.2.3.4", defaultRoute: nat, worldOpenInbound: open });
    expect(priv).toMatchObject({ inboundFromInternet: false, outboundToInternet: "via NAT gateway nat-1" });
    expect(priv.summary).toMatch(/no route to an internet gateway/);
  });
});

describe("ec2 module", () => {
  it("TS tools are read-only; markdown tools load from the folder", async () => {
    const mod = createEc2Module(fakeFactory({}).factory);
    expect(mod.tools.map((t) => t.name)).toEqual(["trace_instance_network", "find_open_security_groups"]);
    const md = await loadMarkdownTools(join(__dirname, "..", "src", "services", "ec2"), fakeFactory({}).factory);
    expect(md.map((t) => t.name).sort()).toEqual([
      "describe_route_tables",
      "describe_security_groups",
      "list_instances",
      "list_nat_gateways",
      "list_subnets",
      "list_vpc_endpoints",
      "list_vpcs",
    ]);
    for (const t of [...mod.tools, ...md]) expect(t.risk).toBe("read");
  });

  it("trace_instance_network: private instance behind an ALB", async () => {
    const { factory } = fakeFactory({
      DescribeInstancesCommand: {
        Reservations: [
          {
            Instances: [
              {
                InstanceId: "i-0abc",
                State: { Name: "running" },
                VpcId: "vpc-1",
                SubnetId: "subnet-priv",
                PrivateIpAddress: "10.0.2.15",
                SecurityGroups: [{ GroupId: "sg-ssh" }],
                Tags: [{ Key: "Name", Value: "api-1" }],
              },
            ],
          },
        ],
      },
      DescribeVpcsCommand: { Vpcs: [{ VpcId: "vpc-1", CidrBlock: "10.0.0.0/16", IsDefault: false }] },
      DescribeSubnetsCommand: { Subnets: [{ SubnetId: "subnet-priv", CidrBlock: "10.0.2.0/24", AvailabilityZone: "ap-south-1a" }] },
      DescribeRouteTablesCommand: { RouteTables: [MAIN_RT, PRIVATE_RT] },
      DescribeSecurityGroupsCommand: { SecurityGroups: [SSH_OPEN] },
      DescribeTargetGroupsCommand: {
        TargetGroups: [{ TargetGroupArn: "arn:tg/api/1", TargetGroupName: "api", LoadBalancerArns: ["arn:lb/app/web/1"] }],
      },
      DescribeTargetHealthCommand: {
        TargetHealthDescriptions: [{ Target: { Id: "i-0abc", Port: 8080 }, TargetHealth: { State: "healthy" } }],
      },
      DescribeLoadBalancersCommand: {
        LoadBalancers: [{ LoadBalancerArn: "arn:lb/app/web/1", LoadBalancerName: "web", Scheme: "internet-facing" }],
      },
    });
    const trace = createEc2Module(factory).tools[0];
    const out = (await trace.handler({ instanceId: "i-0abc" }, ctx)) as any;

    expect(out.instance).toMatchObject({ id: "i-0abc", name: "api-1", publicIp: undefined });
    expect(out.routeTable).toMatchObject({ id: "rtb-priv", association: "explicit" });
    expect(out.securityGroups[0].inbound).toContain("tcp 22 from 0.0.0.0/0");
    expect(out.loadBalancers).toEqual([
      expect.objectContaining({ loadBalancer: "web", scheme: "internet-facing", targetGroup: "api", port: 8080, health: "healthy" }),
    ]);
    expect(out.verdict).toMatchObject({ inboundFromInternet: false, outboundToInternet: "via NAT gateway nat-1" });
  });

  it("trace_instance_network: ELB access denied still returns the network trace", async () => {
    const { factory } = fakeFactory({
      DescribeInstancesCommand: {
        Reservations: [{ Instances: [{ InstanceId: "i-1", VpcId: "vpc-1", SubnetId: "subnet-pub", PublicIpAddress: "3.3.3.3", SecurityGroups: [{ GroupId: "sg-ssh" }] }] }],
      },
      DescribeVpcsCommand: { Vpcs: [{ VpcId: "vpc-1" }] },
      DescribeSubnetsCommand: { Subnets: [{ SubnetId: "subnet-pub" }] },
      DescribeRouteTablesCommand: { RouteTables: [MAIN_RT] },
      DescribeSecurityGroupsCommand: { SecurityGroups: [SSH_OPEN] },
      DescribeTargetGroupsCommand: () => new Error("AccessDenied: elasticloadbalancing:DescribeTargetGroups"),
    });
    const out = (await createEc2Module(factory).tools[0].handler({ instanceId: "i-1" }, ctx)) as any;
    expect(out.routeTable.association).toBe("main (implicit)");
    expect(out.loadBalancers.note).toMatch(/AccessDenied/);
    expect(out.verdict.inboundFromInternet).toBe(true);
    expect(out.verdict.summary).toMatch(/REACHABLE.*tcp 22 from 0\.0\.0\.0\/0 \(sg-ssh\)/);
  });

  it("find_open_security_groups ranks high first and counts attachments", async () => {
    const { factory } = fakeFactory({
      DescribeSecurityGroupsCommand: {
        SecurityGroups: [
          SSH_OPEN,
          { GroupId: "sg-closed", IpPermissions: [{ IpProtocol: "tcp", FromPort: 22, ToPort: 22, IpRanges: [{ CidrIp: "10.0.0.0/8" }] }] },
          { GroupId: "sg-odd", IpPermissions: [{ IpProtocol: "tcp", FromPort: 9000, ToPort: 9000, IpRanges: [{ CidrIp: "0.0.0.0/0" }] }] },
        ],
      },
      DescribeNetworkInterfacesCommand: { NetworkInterfaces: [{ Groups: [{ GroupId: "sg-ssh" }] }, { Groups: [{ GroupId: "sg-ssh" }] }] },
    });
    const out = (await createEc2Module(factory).tools[1].handler({}, ctx)) as any;
    expect(out).toMatchObject({ groupsScanned: 3, high: 1, medium: 1 });
    expect(out.findings.map((f: any) => [f.groupId, f.severity, f.attachedInterfaces])).toEqual([
      ["sg-ssh", "high", 2],
      ["sg-odd", "medium", 0],
    ]);
  });
});
