import type { HostedZone, ResourceRecordSet } from "@aws-sdk/client-route-53";

/** Pure DNS helpers — unit-tested in tests/route53.test.ts. */

/** "API.Example.com." -> "api.example.com"; also undoes Route 53's "\052" escape for "*". */
export const normalizeDns = (name: string) =>
  name.trim().toLowerCase().replace(/\\052/g, "*").replace(/\.$/, "").replace(/^dualstack\./, "");

/** The most specific hosted zone that contains `domain` (public zones preferred on ties). */
export function zoneForDomain(zones: HostedZone[], domain: string): HostedZone | undefined {
  const d = normalizeDns(domain);
  return zones
    .filter((z) => {
      const zn = normalizeDns(z.Name ?? "");
      return d === zn || d.endsWith(`.${zn}`);
    })
    .sort(
      (a, b) =>
        normalizeDns(b.Name ?? "").length - normalizeDns(a.Name ?? "").length ||
        Number(a.Config?.PrivateZone ?? false) - Number(b.Config?.PrivateZone ?? false),
    )[0];
}

/** Exact record for `domain`, falling back to a wildcard (*.parent) record. */
export function findRecords(records: ResourceRecordSet[], domain: string): { records: ResourceRecordSet[]; viaWildcard: boolean } {
  const d = normalizeDns(domain);
  const usable = records.filter((r) => ["A", "AAAA", "CNAME"].includes(r.Type ?? ""));
  const exact = usable.filter((r) => normalizeDns(r.Name ?? "") === d);
  if (exact.length) return { records: exact, viaWildcard: false };
  const wildcard = `*.${d.split(".").slice(1).join(".")}`;
  return { records: usable.filter((r) => normalizeDns(r.Name ?? "") === wildcard), viaWildcard: true };
}

export type TargetKind = "load-balancer" | "cloudfront" | "s3-website" | "api-gateway" | "elastic-beanstalk" | "ip" | "hostname";

export function classifyTarget(value: string): TargetKind {
  const v = normalizeDns(value);
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(v) || v.includes(":")) return "ip";
  if (v.endsWith(".elb.amazonaws.com")) return "load-balancer";
  if (v.endsWith(".cloudfront.net")) return "cloudfront";
  if (v.includes(".s3-website")) return "s3-website";
  if (v.includes(".execute-api.") || v.startsWith("d-") && v.includes(".apigateway")) return "api-gateway";
  if (v.endsWith(".elasticbeanstalk.com")) return "elastic-beanstalk";
  return "hostname";
}

/** Where a record points: alias target or its values. */
export const recordTargets = (r: ResourceRecordSet): string[] =>
  r.AliasTarget?.DNSName ? [r.AliasTarget.DNSName] : (r.ResourceRecords ?? []).map((x) => x.Value!).filter(Boolean);

/** Does a certificate name (possibly "*.example.com") cover `domain`? Wildcards match one label only. */
export function certCovers(certName: string, domain: string): boolean {
  const c = normalizeDns(certName);
  const d = normalizeDns(domain);
  if (c === d) return true;
  if (!c.startsWith("*.")) return false;
  const rest = d.split(".").slice(1).join(".");
  return c.slice(2) === rest;
}

/** Region of an ELB from its DNS name: name-123.ap-south-1.elb.amazonaws.com. */
export const elbRegion = (dns: string) => /\.([a-z]{2}-[a-z]+-\d)\.elb\.amazonaws\.com$/.exec(normalizeDns(dns))?.[1];
