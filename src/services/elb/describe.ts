import {
  ElasticLoadBalancingV2Client,
  DescribeLoadBalancersCommand,
  DescribeTargetGroupsCommand,
  DescribeTargetHealthCommand,
  DescribeListenersCommand,
  DescribeRulesCommand,
  type Rule,
  type Action,
  type RuleCondition,
  type TargetGroup,
  type LoadBalancer,
  type RedirectActionConfig,
} from "@aws-sdk/client-elastic-load-balancing-v2";
import { mapLimited } from "../../core/helpers.js";

export { mapLimited };

/** "arn:...:targetgroup/api-tg/abc123" -> "api-tg" (also works for loadbalancer ARNs). */
export const nameFromArn = (arn?: string) => {
  if (!arn) return "unknown";
  const parts = arn.split("/");
  return arn.includes(":loadbalancer/") ? parts[2] : parts[1];
};

/** One readable line per listener/rule action. */
export function describeAction(a: Action): string {
  switch (a.Type) {
    case "forward": {
      const weighted = a.ForwardConfig?.TargetGroups ?? [];
      const groups = weighted.length
        ? weighted.map((g) =>
            weighted.length > 1 ? `${nameFromArn(g.TargetGroupArn)} (weight ${g.Weight ?? 1})` : nameFromArn(g.TargetGroupArn),
          )
        : [nameFromArn(a.TargetGroupArn)];
      return `forward -> ${groups.join(", ")}`;
    }
    case "redirect": {
      const r: RedirectActionConfig = a.RedirectConfig ?? ({} as RedirectActionConfig);
      const url = `${r.Protocol ?? "#{protocol}"}://${r.Host ?? "#{host}"}:${r.Port ?? "#{port}"}${r.Path ?? "/#{path}"}`;
      return r.StatusCode ? `redirect ${r.StatusCode} -> ${url}` : `redirect -> ${url}`;
    }
    case "fixed-response":
      return `fixed response ${a.FixedResponseConfig?.StatusCode ?? ""}`.trim();
    case "authenticate-cognito":
    case "authenticate-oidc":
      return `${a.Type} (login required)`;
    default:
      return a.Type ?? "unknown";
  }
}

/** "host=api.example.com AND path=/v1/*" */
export function describeConditions(conds: RuleCondition[] | undefined): string {
  if (!conds?.length) return "default (no conditions)";
  return conds
    .map((c) => {
      switch (c.Field) {
        case "host-header":
          return `host=${(c.HostHeaderConfig?.Values ?? c.Values ?? []).join("|")}`;
        case "path-pattern":
          return `path=${(c.PathPatternConfig?.Values ?? c.Values ?? []).join("|")}`;
        case "http-header":
          return `header ${c.HttpHeaderConfig?.HttpHeaderName}=${(c.HttpHeaderConfig?.Values ?? []).join("|")}`;
        case "http-request-method":
          return `method=${(c.HttpRequestMethodConfig?.Values ?? []).join("|")}`;
        case "query-string":
          return `query ${(c.QueryStringConfig?.Values ?? []).map((kv) => `${kv.Key ?? "*"}=${kv.Value}`).join("|")}`;
        case "source-ip":
          return `source-ip=${(c.SourceIpConfig?.Values ?? []).join("|")}`;
        default:
          return `${c.Field}=${(c.Values ?? []).join("|")}`;
      }
    })
    .join(" AND ");
}

/** Every target-group ARN an action can forward to. */
export const targetGroupArns = (actions: Action[] | undefined): string[] =>
  (actions ?? []).flatMap((a) =>
    a.Type !== "forward" ? [] : a.ForwardConfig?.TargetGroups?.map((g) => g.TargetGroupArn!) ?? [a.TargetGroupArn!],
  ).filter(Boolean);


export async function allTargetGroups(client: ElasticLoadBalancingV2Client): Promise<TargetGroup[]> {
  const groups: TargetGroup[] = [];
  let Marker: string | undefined;
  do {
    const res = await client.send(new DescribeTargetGroupsCommand({ PageSize: 400, Marker }));
    groups.push(...(res.TargetGroups ?? []));
    Marker = res.NextMarker;
  } while (Marker);
  return groups;
}

export async function loadBalancersByArn(
  client: ElasticLoadBalancingV2Client,
  arns: string[],
): Promise<Map<string, LoadBalancer>> {
  const map = new Map<string, LoadBalancer>();
  const unique = [...new Set(arns)];
  for (let i = 0; i < unique.length; i += 20) {
    const res = await client.send(new DescribeLoadBalancersCommand({ LoadBalancerArns: unique.slice(i, i + 20) }));
    for (const lb of res.LoadBalancers ?? []) map.set(lb.LoadBalancerArn!, lb);
  }
  return map;
}

/**
 * Reverse lookup: which load balancers / target groups route to this target
 * (instance id or IP). Scans target groups attached to a load balancer.
 */
export async function findLoadBalancersForTarget(client: ElasticLoadBalancingV2Client, targetId: string) {
  const groups = (await allTargetGroups(client)).filter((g) => g.LoadBalancerArns?.length);
  const matches = (
    await mapLimited(groups, 10, async (g) => {
      const res = await client.send(new DescribeTargetHealthCommand({ TargetGroupArn: g.TargetGroupArn }));
      return (res.TargetHealthDescriptions ?? [])
        .filter((d) => d.Target?.Id === targetId)
        .map((d) => ({ group: g, port: d.Target?.Port, health: d.TargetHealth?.State, reason: d.TargetHealth?.Reason }));
    })
  ).flat();

  const lbs = await loadBalancersByArn(client, matches.flatMap((m) => m.group.LoadBalancerArns ?? []));
  return {
    targetGroupsScanned: groups.length,
    matches: matches.flatMap((m) =>
      (m.group.LoadBalancerArns ?? []).map((arn) => {
        const lb = lbs.get(arn);
        return {
          loadBalancer: lb?.LoadBalancerName ?? nameFromArn(arn),
          type: lb?.Type,
          scheme: lb?.Scheme,
          dns: lb?.DNSName,
          targetGroup: m.group.TargetGroupName,
          port: m.port,
          health: m.health,
          reason: m.reason,
        };
      }),
    ),
  };
}

/**
 * Full routing map of one load balancer: listeners -> rules -> target groups
 * -> targets with health. Shared by elb_map_load_balancer and the Route 53
 * domain trace.
 */
export async function mapLoadBalancer(client: ElasticLoadBalancingV2Client, name: string) {
  const lbRes = await client.send(new DescribeLoadBalancersCommand({ Names: [name] }));
  const lb = lbRes.LoadBalancers?.[0];
  if (!lb) throw new Error(`Load balancer "${name}" not found.`);

  const listeners =
    (await client.send(new DescribeListenersCommand({ LoadBalancerArn: lb.LoadBalancerArn }))).Listeners ?? [];

  // Rules exist only for HTTP/HTTPS (ALB) listeners; NLB listeners have just a default action.
  const listenerViews = await mapLimited(listeners, 5, async (l) => {
    let rules: Rule[] = [];
    if (l.Protocol === "HTTP" || l.Protocol === "HTTPS") {
      rules = (await client.send(new DescribeRulesCommand({ ListenerArn: l.ListenerArn }))).Rules ?? [];
    }
    const ordered = [...rules].sort(
      (a, b) => (a.IsDefault ? 1 : 0) - (b.IsDefault ? 1 : 0) || Number(a.Priority) - Number(b.Priority),
    );
    return {
      listener: l,
      tgArns: [...targetGroupArns(l.DefaultActions), ...rules.flatMap((r) => targetGroupArns(r.Actions))],
      view: {
        port: l.Port,
        protocol: l.Protocol,
        certificates: l.Certificates?.map((c) => c.CertificateArn),
        rules: ordered.length
          ? ordered.map((r) => ({
              priority: r.Priority,
              when: describeConditions(r.Conditions),
              then: (r.Actions ?? []).map(describeAction).join("; "),
            }))
          : [{ priority: "default", when: "default (no conditions)", then: (l.DefaultActions ?? []).map(describeAction).join("; ") }],
      },
    };
  });

  const tgArns = [...new Set(listenerViews.flatMap((v) => v.tgArns))];
  const groups = [];
  for (let i = 0; i < tgArns.length; i += 20) {
    const res = await client.send(new DescribeTargetGroupsCommand({ TargetGroupArns: tgArns.slice(i, i + 20) }));
    groups.push(...(res.TargetGroups ?? []));
  }
  const targetGroups = await mapLimited(groups, 10, async (g) => {
    const health = (await client.send(new DescribeTargetHealthCommand({ TargetGroupArn: g.TargetGroupArn })))
      .TargetHealthDescriptions ?? [];
    const targets = health.map((d) => ({
      id: d.Target?.Id,
      port: d.Target?.Port,
      state: d.TargetHealth?.State,
      reason: d.TargetHealth?.Reason,
    }));
    return {
      name: g.TargetGroupName,
      protocol: g.Protocol,
      port: g.Port,
      targetType: g.TargetType,
      healthCheck: `${g.HealthCheckProtocol ?? ""} ${g.HealthCheckPort ?? ""} ${g.HealthCheckPath ?? ""}`.trim(),
      healthy: targets.filter((t) => t.state === "healthy").length,
      unhealthy: targets.filter((t) => t.state === "unhealthy").length,
      targets,
    };
  });

  return {
    loadBalancer: {
      name: lb.LoadBalancerName,
      type: lb.Type,
      scheme: lb.Scheme,
      state: lb.State?.Code,
      dns: lb.DNSName,
      vpcId: lb.VpcId,
      securityGroups: lb.SecurityGroups,
    },
    listeners: listenerViews.map((v) => v.view),
    targetGroups,
    warnings: targetGroups
      .filter((g) => g.targets.length === 0 || g.unhealthy > 0)
      .map((g) => (g.targets.length === 0 ? `${g.name}: no registered targets` : `${g.name}: ${g.unhealthy} unhealthy target(s)`)),
  };
}
