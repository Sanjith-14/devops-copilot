import {
  ElasticLoadBalancingV2Client,
  DescribeLoadBalancersCommand,
  DescribeTargetGroupsCommand,
  DescribeTargetHealthCommand,
  type Action,
  type RuleCondition,
  type TargetGroup,
  type LoadBalancer,
  type RedirectActionConfig,
} from "@aws-sdk/client-elastic-load-balancing-v2";

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

/** Run async work over items with bounded concurrency (be nice to API rate limits). */
export async function mapLimited<T, R>(items: T[], limit: number, fn: (item: T) => Promise<R>): Promise<R[]> {
  const out: R[] = [];
  for (let i = 0; i < items.length; i += limit) out.push(...(await Promise.all(items.slice(i, i + limit).map(fn))));
  return out;
}

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
