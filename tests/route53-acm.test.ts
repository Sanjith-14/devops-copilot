import { describe, it, expect } from "vitest";
import createRoute53Module from "../src/services/route53/index.js";
import { certCovers, classifyTarget, elbRegion, findRecords, normalizeDns, zoneForDomain } from "../src/services/route53/dns.js";
import { certificateFindings } from "../src/services/acm/tools.js";
import { fakeFactory, ctx } from "./fake-aws.js";

const ZONES = [
  { Id: "/hostedzone/Z1", Name: "example.com.", Config: { PrivateZone: false } },
  { Id: "/hostedzone/Z2", Name: "api.example.com.", Config: { PrivateZone: false } },
  { Id: "/hostedzone/Z3", Name: "example.com.", Config: { PrivateZone: true } },
];
const LB_DNS = "web-alb-123.ap-south-1.elb.amazonaws.com";

describe("dns helpers", () => {
  it("normalizes names", () => {
    expect(normalizeDns("API.Example.com.")).toBe("api.example.com");
    expect(normalizeDns("\\052.example.com.")).toBe("*.example.com");
    expect(normalizeDns(`dualstack.${LB_DNS}.`)).toBe(LB_DNS);
  });

  it("picks the most specific public zone", () => {
    expect(zoneForDomain(ZONES, "v1.api.example.com")?.Id).toBe("/hostedzone/Z2");
    expect(zoneForDomain(ZONES, "www.example.com")?.Id).toBe("/hostedzone/Z1");
    expect(zoneForDomain(ZONES, "other.org")).toBeUndefined();
  });

  it("finds exact then wildcard records", () => {
    const recs = [
      { Name: "\\052.example.com.", Type: "CNAME", ResourceRecords: [{ Value: "x" }] },
      { Name: "www.example.com.", Type: "A" },
      { Name: "www.example.com.", Type: "TXT" },
    ];
    expect(findRecords(recs, "www.example.com")).toMatchObject({ viaWildcard: false, records: [{ Type: "A" }] });
    expect(findRecords(recs, "shop.example.com")).toMatchObject({ viaWildcard: true, records: [{ Type: "CNAME" }] });
  });

  it("classifies targets and certificate coverage", () => {
    expect(classifyTarget(`dualstack.${LB_DNS}.`)).toBe("load-balancer");
    expect(classifyTarget("d111.cloudfront.net")).toBe("cloudfront");
    expect(classifyTarget("10.0.0.5")).toBe("ip");
    expect(elbRegion(LB_DNS)).toBe("ap-south-1");
    expect(certCovers("*.example.com", "api.example.com")).toBe(true);
    expect(certCovers("*.example.com", "v1.api.example.com")).toBe(false);
    expect(certCovers("example.com", "example.com")).toBe(true);
  });
});

describe("route53_trace_domain", () => {
  it("DNS alias -> ALB map -> certificate", async () => {
    const { factory } = fakeFactory({
      ListHostedZonesCommand: { HostedZones: ZONES },
      ListResourceRecordSetsCommand: {
        ResourceRecordSets: [{ Name: "api.example.com.", Type: "A", AliasTarget: { DNSName: `dualstack.${LB_DNS}.` } }],
      },
      DescribeLoadBalancersCommand: (input: { Names?: string[] }) => ({
        LoadBalancers: [{ LoadBalancerName: "web-alb", LoadBalancerArn: "arn:lb", DNSName: LB_DNS, Scheme: "internet-facing" }],
        ...(input.Names ? {} : {}),
      }),
      DescribeListenersCommand: { Listeners: [{ Port: 443, Protocol: "HTTPS", ListenerArn: "l1", DefaultActions: [{ Type: "forward", TargetGroupArn: "arn:x:targetgroup/api/1" }] }] },
      DescribeRulesCommand: { Rules: [] },
      DescribeTargetGroupsCommand: { TargetGroups: [{ TargetGroupArn: "arn:x:targetgroup/api/1", TargetGroupName: "api" }] },
      DescribeTargetHealthCommand: { TargetHealthDescriptions: [{ Target: { Id: "i-1", Port: 80 }, TargetHealth: { State: "healthy" } }] },
      ListCertificatesCommand: {
        CertificateSummaryList: [
          { DomainName: "*.example.com", Status: "ISSUED", Type: "AMAZON_ISSUED", InUse: true, NotAfter: new Date(Date.now() + 40 * 86_400_000) },
          { DomainName: "other.org", NotAfter: new Date() },
        ],
      },
    });
    const out = (await createRoute53Module(factory).tools[0].handler({ domain: "API.example.com" }, ctx)) as any;
    expect(out.dns[0]).toMatchObject({ name: "api.example.com", zone: "api.example.com", records: [{ type: "A", alias: true, targets: [LB_DNS] }] });
    expect(out.pointsTo).toEqual([{ target: LB_DNS, kind: "load-balancer" }]);
    expect(out.loadBalancers[0]).toMatchObject({ region: "ap-south-1", loadBalancer: { name: "web-alb" } });
    expect(out.loadBalancers[0].targetGroups[0]).toMatchObject({ name: "api", healthy: 1 });
    expect(out.certificates[0]).toMatchObject({ domain: "*.example.com", status: "ISSUED" });
    expect(out.certificates[0].daysLeft).toBeGreaterThanOrEqual(39);
  });

  it("follows CNAME hops inside your zones and reports denied ELB access", async () => {
    const { factory } = fakeFactory({
      ListHostedZonesCommand: { HostedZones: ZONES },
      ListResourceRecordSetsCommand: (i: { StartRecordName: string }) =>
        i.StartRecordName === "www.example.com"
          ? { ResourceRecordSets: [{ Name: "www.example.com.", Type: "CNAME", ResourceRecords: [{ Value: "lb.example.com" }] }] }
          : { ResourceRecordSets: [{ Name: "lb.example.com.", Type: "CNAME", ResourceRecords: [{ Value: LB_DNS }] }] },
      DescribeLoadBalancersCommand: new Error("AccessDenied: not authorized"),
      ListCertificatesCommand: new Error("AccessDeniedException: not authorized"),
    });
    const out = (await createRoute53Module(factory).tools[0].handler({ domain: "www.example.com" }, ctx)) as any;
    expect(out.dns.map((h: any) => h.name)).toEqual(["www.example.com", "lb.example.com"]);
    expect(out.loadBalancers[0].skipped).toMatch(/no permission/);
    expect(out.certificates.skipped).toMatch(/no permission/);
  });
});

describe("acm expiry findings", () => {
  const now = Date.parse("2026-10-15T00:00:00Z");
  const inDays = (d: number) => new Date(now + d * 86_400_000);
  it("flags expired, imported, and auto-renewing certs differently", () => {
    const f = certificateFindings(
      [
        { DomainName: "old.com", NotAfter: inDays(-3), InUse: true },
        { DomainName: "imp.com", NotAfter: inDays(10), Type: "IMPORTED" },
        { DomainName: "auto.com", NotAfter: inDays(20), Type: "AMAZON_ISSUED", RenewalEligibility: "ELIGIBLE" },
        { DomainName: "far.com", NotAfter: inDays(200) },
      ],
      30,
      now,
    );
    expect(f.map((x) => [x.resource, x.severity])).toEqual([
      ["acm:old.com", "high"],
      ["acm:imp.com", "high"],
      ["acm:auto.com", "info"],
    ]);
    expect(f[1].issue).toMatch(/IMPORTED/);
  });
});
