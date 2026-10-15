import {
  Route53Client,
  ListHostedZonesCommand,
  ListResourceRecordSetsCommand,
  type HostedZone,
} from "@aws-sdk/client-route-53";
import { ElasticLoadBalancingV2Client, DescribeLoadBalancersCommand, type LoadBalancer } from "@aws-sdk/client-elastic-load-balancing-v2";
import { ACMClient, ListCertificatesCommand, type CertificateSummary } from "@aws-sdk/client-acm";
import { z } from "zod";
import type { ToolDefinition, ToolContext } from "../../core/types.js";
import type { AwsClientFactory } from "../../core/aws-client.js";
import { bestEffort, daysSince } from "../../core/helpers.js";
import { mapLoadBalancer } from "../elb/describe.js";
import { certCovers, classifyTarget, elbRegion, findRecords, normalizeDns, recordTargets, zoneForDomain } from "./dns.js";

const MAX_CNAME_HOPS = 3;

export const ALL_KEY_TYPES = [
  "RSA_1024",
  "RSA_2048",
  "RSA_3072",
  "RSA_4096",
  "EC_prime256v1",
  "EC_secp384r1",
  "EC_secp521r1",
] as const;

export async function allCertificates(acm: ACMClient): Promise<CertificateSummary[]> {
  const certs: CertificateSummary[] = [];
  let NextToken: string | undefined;
  do {
    const res = await acm.send(
      new ListCertificatesCommand({ MaxItems: 1000, NextToken, Includes: { keyTypes: [...ALL_KEY_TYPES] } }),
    );
    certs.push(...(res.CertificateSummaryList ?? []));
    NextToken = res.NextToken;
  } while (NextToken);
  return certs;
}

export function buildRoute53Tools(factory: AwsClientFactory): ToolDefinition[] {
  const get = <T>(Ctor: new (c: never) => T, ctx: ToolContext, region = ctx.region) =>
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    factory.getClient(Ctor as any, ctx.accountId, region).client as T;

  return [
    {
      name: "trace_domain",
      description:
        "Follow a domain name end-to-end: Route 53 hosted zone -> DNS record (alias/CNAME, following up to 3 " +
        "CNAME hops inside your zones) -> what it points to (load balancer, CloudFront, S3 website, API Gateway, IP). " +
        "For a load balancer it includes the full listener -> rule -> target group -> target health map, and it " +
        "reports the ACM certificate covering the domain with days until expiry. Answers 'where does api.example.com go?'.",
      risk: "read",
      inputSchema: {
        domain: z.string().max(253).describe("Fully qualified domain, e.g. api.example.com"),
      },
      handler: async (args, ctx) => {
        const domain = normalizeDns(args.domain as string);
        const r53 = get(Route53Client, ctx, "us-east-1");

        const zones: HostedZone[] = [];
        let Marker: string | undefined;
        do {
          const res = await r53.send(new ListHostedZonesCommand({ Marker }));
          zones.push(...(res.HostedZones ?? []));
          Marker = res.IsTruncated ? res.NextMarker : undefined;
        } while (Marker);

        const hops: Record<string, unknown>[] = [];
        let name = domain;
        let finalTargets: string[] = [];
        for (let hop = 0; hop <= MAX_CNAME_HOPS; hop++) {
          const zone = zoneForDomain(zones, name);
          if (!zone) {
            hops.push({ name, note: "not in any Route 53 hosted zone in this account — resolved elsewhere" });
            finalTargets = hop === 0 ? [] : [name];
            break;
          }
          const res = await r53.send(
            new ListResourceRecordSetsCommand({ HostedZoneId: zone.Id, StartRecordName: name, MaxItems: 50 }),
          );
          let { records, viaWildcard } = findRecords(res.ResourceRecordSets ?? [], name);
          if (!records.length && viaWildcard) {
            const wildcard = `*.${name.split(".").slice(1).join(".")}`;
            const wres = await r53.send(
              new ListResourceRecordSetsCommand({ HostedZoneId: zone.Id, StartRecordName: wildcard, MaxItems: 50 }),
            );
            ({ records, viaWildcard } = findRecords(wres.ResourceRecordSets ?? [], name));
          }
          if (!records.length) {
            hops.push({ name, zone: zone.Name, privateZone: zone.Config?.PrivateZone, note: "no A/AAAA/CNAME record found" });
            break;
          }
          const targets = [...new Set(records.flatMap(recordTargets).map(normalizeDns))];
          hops.push({
            name,
            zone: normalizeDns(zone.Name ?? ""),
            privateZone: zone.Config?.PrivateZone,
            viaWildcard: viaWildcard || undefined,
            records: records.map((r) => ({
              type: r.Type,
              alias: Boolean(r.AliasTarget) || undefined,
              ttl: r.TTL,
              targets: recordTargets(r).map(normalizeDns),
              routing: r.SetIdentifier ? { id: r.SetIdentifier, weight: r.Weight, region: r.Region, failover: r.Failover } : undefined,
            })),
          });
          finalTargets = targets;
          const next = records.every((r) => r.Type === "CNAME" && !r.AliasTarget) && targets.length === 1 ? targets[0] : undefined;
          if (!next || classifyTarget(next) !== "hostname" || !zoneForDomain(zones, next)) break;
          name = next;
        }

        const pointsTo = finalTargets.map((t) => ({ target: t, kind: classifyTarget(t) }));

        // Load balancers: find by DNS name in the LB's own region, then map it.
        const lbTargets = pointsTo.filter((p) => p.kind === "load-balancer");
        const loadBalancers = lbTargets.length
          ? await Promise.all(
              lbTargets.map(async (p) => {
                const region = elbRegion(p.target) ?? ctx.region;
                const r = await bestEffort(async () => {
                  const elb = get(ElasticLoadBalancingV2Client, ctx, region);
                  const all: LoadBalancer[] = [];
                  let NextMarker: string | undefined;
                  do {
                    const res = await elb.send(new DescribeLoadBalancersCommand({ Marker: NextMarker, PageSize: 400 }));
                    all.push(...(res.LoadBalancers ?? []));
                    NextMarker = res.NextMarker;
                  } while (NextMarker);
                  const lb = all.find((l) => normalizeDns(l.DNSName ?? "") === p.target);
                  if (!lb) return { note: `no load balancer with DNS ${p.target} in ${region} for this account` };
                  return mapLoadBalancer(elb, lb.LoadBalancerName!);
                });
                return { dns: p.target, region, ...(r.status === "checked" ? r.data : { skipped: r.reason }) };
              }),
            )
          : undefined;

        // Certificate covering the domain (in the LB's region, plus us-east-1 for CloudFront).
        const certRegions = [...new Set([...(lbTargets.map((p) => elbRegion(p.target) ?? ctx.region)), ctx.region, "us-east-1"])];
        const certificate = await bestEffort(async () => {
          const found = [];
          for (const region of certRegions) {
            for (const c of await allCertificates(get(ACMClient, ctx, region))) {
              const names = [c.DomainName ?? "", ...(c.SubjectAlternativeNameSummaries ?? [])];
              if (names.some((n) => certCovers(n, domain))) {
                found.push({ region, domain: c.DomainName, status: c.Status, type: c.Type, inUse: c.InUse, expires: c.NotAfter, daysLeft: c.NotAfter ? -(daysSince(c.NotAfter) ?? 0) : undefined });
              }
            }
          }
          return found;
        });

        return {
          domain,
          dns: hops,
          pointsTo,
          loadBalancers,
          certificates: certificate.status === "checked" ? certificate.data : { skipped: certificate.reason },
        };
      },
    },
  ];
}
