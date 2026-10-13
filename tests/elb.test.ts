import { describe, it, expect } from "vitest";
import { join } from "node:path";
import createElbModule from "../src/services/elb/index.js";
import { loadMarkdownTools } from "../src/core/md-tools.js";
import { describeAction, describeConditions, nameFromArn, targetGroupArns } from "../src/services/elb/describe.js";
import { fakeFactory, ctx } from "./fake-aws.js";

const TG_API = "arn:aws:elasticloadbalancing:ap-south-1:1:targetgroup/api-tg/abc";
const TG_WEB = "arn:aws:elasticloadbalancing:ap-south-1:1:targetgroup/web-tg/def";
const LB_ARN = "arn:aws:elasticloadbalancing:ap-south-1:1:loadbalancer/app/web-alb/123";

describe("elb helpers", () => {
  it("extracts names from ARNs", () => {
    expect(nameFromArn(TG_API)).toBe("api-tg");
    expect(nameFromArn(LB_ARN)).toBe("web-alb");
  });

  it("describes actions", () => {
    expect(describeAction({ Type: "forward", TargetGroupArn: TG_API })).toBe("forward -> api-tg");
    expect(
      describeAction({
        Type: "forward",
        ForwardConfig: { TargetGroups: [{ TargetGroupArn: TG_API, Weight: 90 }, { TargetGroupArn: TG_WEB, Weight: 10 }] },
      }),
    ).toBe("forward -> api-tg (weight 90), web-tg (weight 10)");
    expect(describeAction({ Type: "redirect", RedirectConfig: { Protocol: "HTTPS", Port: "443", StatusCode: "HTTP_301" } })).toBe(
      "redirect HTTP_301 -> HTTPS://#{host}:443/#{path}",
    );
    expect(describeAction({ Type: "fixed-response", FixedResponseConfig: { StatusCode: "404" } })).toBe("fixed response 404");
  });

  it("describes conditions", () => {
    expect(describeConditions(undefined)).toBe("default (no conditions)");
    expect(
      describeConditions([
        { Field: "host-header", HostHeaderConfig: { Values: ["api.example.com"] } },
        { Field: "path-pattern", Values: ["/v1/*"] },
      ]),
    ).toBe("host=api.example.com AND path=/v1/*");
  });

  it("collects target groups from simple and weighted forwards", () => {
    expect(
      targetGroupArns([
        { Type: "forward", TargetGroupArn: TG_API },
        { Type: "forward", ForwardConfig: { TargetGroups: [{ TargetGroupArn: TG_WEB }] } },
        { Type: "redirect" },
      ]),
    ).toEqual([TG_API, TG_WEB]);
  });
});

describe("elb module", () => {
  it("TS + markdown tools, all read-only", async () => {
    const mod = createElbModule(fakeFactory({}).factory);
    expect(mod.tools.map((t) => t.name)).toEqual(["map_load_balancer", "find_load_balancers_for_target"]);
    const md = await loadMarkdownTools(join(__dirname, "..", "src", "services", "elb"), fakeFactory({}).factory);
    expect(md.map((t) => t.name).sort()).toEqual([
      "get_target_health",
      "list_listeners",
      "list_load_balancers",
      "list_target_groups",
    ]);
    for (const t of [...mod.tools, ...md]) expect(t.risk).toBe("read");
  });

  it("map_load_balancer builds listener -> rule -> target group -> target view", async () => {
    const { factory } = fakeFactory({
      DescribeLoadBalancersCommand: {
        LoadBalancers: [{ LoadBalancerArn: LB_ARN, LoadBalancerName: "web-alb", Type: "application", Scheme: "internet-facing" }],
      },
      DescribeListenersCommand: {
        Listeners: [
          { ListenerArn: "l-80", Port: 80, Protocol: "HTTP", DefaultActions: [{ Type: "redirect", RedirectConfig: { Protocol: "HTTPS", Port: "443", StatusCode: "HTTP_301" } }] },
          { ListenerArn: "l-443", Port: 443, Protocol: "HTTPS", DefaultActions: [{ Type: "forward", TargetGroupArn: TG_WEB }] },
        ],
      },
      DescribeRulesCommand: (input: { ListenerArn: string }) =>
        input.ListenerArn === "l-443"
          ? {
              Rules: [
                { Priority: "default", IsDefault: true, Actions: [{ Type: "forward", TargetGroupArn: TG_WEB }] },
                { Priority: "10", Conditions: [{ Field: "path-pattern", Values: ["/api/*"] }], Actions: [{ Type: "forward", TargetGroupArn: TG_API }] },
              ],
            }
          : { Rules: [{ Priority: "default", IsDefault: true, Actions: [{ Type: "redirect", RedirectConfig: { Protocol: "HTTPS", Port: "443" } }] }] },
      DescribeTargetGroupsCommand: {
        TargetGroups: [
          { TargetGroupArn: TG_WEB, TargetGroupName: "web-tg", Port: 80, Protocol: "HTTP" },
          { TargetGroupArn: TG_API, TargetGroupName: "api-tg", Port: 8080, Protocol: "HTTP", HealthCheckPath: "/health" },
        ],
      },
      DescribeTargetHealthCommand: (input: { TargetGroupArn: string }) =>
        input.TargetGroupArn === TG_API
          ? {
              TargetHealthDescriptions: [
                { Target: { Id: "i-1", Port: 8080 }, TargetHealth: { State: "healthy" } },
                { Target: { Id: "i-2", Port: 8080 }, TargetHealth: { State: "unhealthy", Reason: "Target.FailedHealthChecks" } },
              ],
            }
          : { TargetHealthDescriptions: [] },
    });
    const out = (await createElbModule(factory).tools[0].handler({ name: "web-alb" }, ctx)) as any;

    expect(out.loadBalancer).toMatchObject({ name: "web-alb", scheme: "internet-facing" });
    expect(out.listeners[1].rules).toEqual([
      { priority: "10", when: "path=/api/*", then: "forward -> api-tg" },
      { priority: "default", when: "default (no conditions)", then: "forward -> web-tg" },
    ]);
    const api = out.targetGroups.find((g: any) => g.name === "api-tg");
    expect(api).toMatchObject({ healthy: 1, unhealthy: 1 });
    expect(out.warnings).toEqual(expect.arrayContaining(["web-tg: no registered targets", "api-tg: 1 unhealthy target(s)"]));
  });

  it("find_load_balancers_for_target reports no match cleanly", async () => {
    const { factory } = fakeFactory({
      DescribeTargetGroupsCommand: { TargetGroups: [{ TargetGroupArn: TG_API, LoadBalancerArns: [LB_ARN] }] },
      DescribeTargetHealthCommand: { TargetHealthDescriptions: [{ Target: { Id: "i-other" } }] },
      DescribeLoadBalancersCommand: { LoadBalancers: [] },
    });
    const out = (await createElbModule(factory).tools[1].handler({ target: "i-1" }, ctx)) as any;
    expect(out).toMatchObject({ behindLoadBalancers: false, targetGroupsScanned: 1, matches: [] });
  });
});
