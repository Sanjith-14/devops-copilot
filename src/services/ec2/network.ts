import type { IpPermission, Route, RouteTable, Tag } from "@aws-sdk/client-ec2";

/**
 * Pure VPC-networking logic (no AWS calls) — unit-tested against sample
 * responses in tests/ec2.test.ts.
 */

export const nameTag = (tags?: Tag[]) => tags?.find((t) => t.Key === "Name")?.Value;

const TARGET_KINDS: [string, string][] = [
  ["igw-", "internet-gateway"],
  ["eigw-", "egress-only-internet-gateway"],
  ["nat-", "nat-gateway"],
  ["tgw-", "transit-gateway"],
  ["pcx-", "vpc-peering"],
  ["vpce-", "vpc-endpoint"],
  ["eni-", "network-interface"],
  ["i-", "instance"],
  ["vgw-", "vpn-gateway"],
  ["lgw-", "local-gateway"],
  ["cagw-", "carrier-gateway"],
];

/** Flatten a route to { destination, target, kind, state }. */
export function describeRoute(r: Route) {
  const target =
    r.GatewayId ??
    r.NatGatewayId ??
    r.TransitGatewayId ??
    r.VpcPeeringConnectionId ??
    r.EgressOnlyInternetGatewayId ??
    r.NetworkInterfaceId ??
    r.InstanceId ??
    r.LocalGatewayId ??
    r.CarrierGatewayId ??
    "unknown";
  const kind = target === "local" ? "local" : (TARGET_KINDS.find(([p]) => target.startsWith(p))?.[1] ?? "other");
  return {
    destination: r.DestinationCidrBlock ?? r.DestinationIpv6CidrBlock ?? r.DestinationPrefixListId ?? "unknown",
    target,
    kind,
    state: r.State,
  };
}

/**
 * The route table that actually applies to a subnet: its explicit
 * association, otherwise the VPC's main table (the part people forget).
 */
export function routeTableForSubnet(
  tables: RouteTable[],
  subnetId: string,
): { table?: RouteTable; association: "explicit" | "main (implicit)" } {
  const explicit = tables.find((t) => t.Associations?.some((a) => a.SubnetId === subnetId));
  if (explicit) return { table: explicit, association: "explicit" };
  return { table: tables.find((t) => t.Associations?.some((a) => a.Main)), association: "main (implicit)" };
}

/** The active 0.0.0.0/0 (or ::/0) route of a table, if any. */
export function defaultRoute(table?: RouteTable) {
  const r = table?.Routes?.find(
    (r) => (r.DestinationCidrBlock === "0.0.0.0/0" || r.DestinationIpv6CidrBlock === "::/0") && r.State !== "blackhole",
  );
  return r ? describeRoute(r) : undefined;
}

const WORLD = new Set(["0.0.0.0/0", "::/0"]);

function portLabel(p: IpPermission): string {
  if (p.IpProtocol === "-1") return "all traffic";
  const proto = p.IpProtocol ?? "?";
  if (p.FromPort == null || p.FromPort === -1) return proto;
  if (p.FromPort === 0 && p.ToPort === 65535) return `${proto} all ports`;
  return p.FromPort === p.ToPort ? `${proto} ${p.FromPort}` : `${proto} ${p.FromPort}-${p.ToPort}`;
}

function peers(p: IpPermission): string[] {
  return [
    ...(p.IpRanges ?? []).map((r) => r.CidrIp!),
    ...(p.Ipv6Ranges ?? []).map((r) => r.CidrIpv6!),
    ...(p.UserIdGroupPairs ?? []).map((g) => g.GroupId!),
    ...(p.PrefixListIds ?? []).map((pl) => pl.PrefixListId!),
  ].filter(Boolean);
}

/** One readable line per (rule, peer): "tcp 443 from 0.0.0.0/0". */
export function summarizeRules(perms: IpPermission[] | undefined, direction: "from" | "to"): string[] {
  return (perms ?? []).flatMap((p) => peers(p).map((peer) => `${portLabel(p)} ${direction} ${peer}`));
}

/** Ports where internet exposure is almost always a mistake. */
export const SENSITIVE_PORTS: Record<number, string> = {
  21: "FTP",
  22: "SSH",
  23: "Telnet",
  445: "SMB",
  1433: "MSSQL",
  1521: "Oracle",
  2375: "Docker API",
  3306: "MySQL",
  3389: "RDP",
  5432: "PostgreSQL",
  5601: "Kibana",
  5900: "VNC",
  6379: "Redis",
  9200: "Elasticsearch",
  11211: "Memcached",
  27017: "MongoDB",
};

export interface OpenRuleFinding {
  rule: string;
  severity: "high" | "medium" | "info";
  reason: string;
}

/** Classify every inbound rule open to 0.0.0.0/0 or ::/0. */
export function findWorldOpenRules(perms: IpPermission[] | undefined): OpenRuleFinding[] {
  const findings: OpenRuleFinding[] = [];
  for (const p of perms ?? []) {
    const world = [...(p.IpRanges ?? []).map((r) => r.CidrIp), ...(p.Ipv6Ranges ?? []).map((r) => r.CidrIpv6)].filter(
      (c): c is string => !!c && WORLD.has(c),
    );
    for (const cidr of world) {
      const rule = `${portLabel(p)} from ${cidr}`;
      const allPorts = p.IpProtocol === "-1" || (p.FromPort === 0 && p.ToPort === 65535);
      if (allPorts) {
        findings.push({ rule, severity: "high", reason: "every port is open to the internet" });
        continue;
      }
      if (p.FromPort == null || p.FromPort === -1) {
        findings.push({ rule, severity: "info", reason: `${p.IpProtocol} open to the internet` });
        continue;
      }
      const hits = Object.entries(SENSITIVE_PORTS)
        .filter(([port]) => +port >= p.FromPort! && +port <= p.ToPort!)
        .map(([port, svc]) => `${svc} (${port})`);
      if (hits.length) findings.push({ rule, severity: "high", reason: `exposes ${hits.join(", ")} to the internet` });
      else if ([80, 443].includes(p.FromPort) && p.FromPort === p.ToPort)
        findings.push({ rule, severity: "info", reason: "public web port — expected for internet-facing load balancers" });
      else findings.push({ rule, severity: "medium", reason: "non-web port open to the internet" });
    }
  }
  return findings;
}

/**
 * Plain-English reachability verdict for an instance. Inbound from the
 * internet needs all three: a public IP, a default route to an internet
 * gateway, and a security group rule open to the world. NACLs not evaluated.
 */
export function exposureVerdict(input: {
  publicIp?: string;
  defaultRoute?: ReturnType<typeof describeRoute>;
  worldOpenInbound: OpenRuleFinding[];
}) {
  const { publicIp, defaultRoute: route, worldOpenInbound } = input;
  const viaIgw = route?.kind === "internet-gateway";

  let outbound: string;
  if (!route) outbound = "none — no default route (isolated subnet)";
  else if (viaIgw) outbound = publicIp ? `direct via ${route.target}` : `none — route to ${route.target} but no public IP`;
  else if (route.kind === "nat-gateway") outbound = `via NAT gateway ${route.target}`;
  else outbound = `via ${route.kind} ${route.target}`;

  const inboundFromInternet = Boolean(publicIp && viaIgw && worldOpenInbound.length > 0);
  const reasons: string[] = [];
  if (!publicIp) reasons.push("no public IP");
  if (!viaIgw) reasons.push("subnet has no route to an internet gateway");
  if (worldOpenInbound.length === 0) reasons.push("no security group rule allows 0.0.0.0/0");

  return {
    inboundFromInternet,
    openPorts: inboundFromInternet ? worldOpenInbound.map((f) => f.rule) : [],
    outboundToInternet: outbound,
    summary: inboundFromInternet
      ? `REACHABLE from the internet on: ${worldOpenInbound.map((f) => f.rule).join("; ")}`
      : `Not directly reachable from the internet (${reasons.join(", ")}). It may still be reachable through a load balancer.`,
    caveat: "Network ACLs are not evaluated.",
  };
}
