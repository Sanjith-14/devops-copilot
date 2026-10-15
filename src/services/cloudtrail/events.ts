import type { Event, LookupAttribute } from "@aws-sdk/client-cloudtrail";
import { redact } from "../../core/aws-ops.js";

/** Pure CloudTrail helpers — unit-tested in tests/cloudtrail.test.ts. */

interface TrailRecord {
  readOnly?: boolean;
  sourceIPAddress?: string;
  errorCode?: string;
  errorMessage?: string;
  userAgent?: string;
  awsRegion?: string;
  userIdentity?: { type?: string; arn?: string; invokedBy?: string; sessionContext?: { sessionIssuer?: { userName?: string } } };
  requestParameters?: unknown;
}

const parseRecord = (raw?: string): TrailRecord => {
  try {
    return raw ? (JSON.parse(raw) as TrailRecord) : {};
  } catch {
    return {};
  }
};

/** Flatten one LookupEvents entry to what a human needs; request params are redacted + truncated. */
export function summarizeEvent(e: Event) {
  const r = parseRecord(e.CloudTrailEvent);
  const params = r.requestParameters ? JSON.stringify(redact(r.requestParameters)) : undefined;
  return {
    time: e.EventTime instanceof Date ? e.EventTime.toISOString() : e.EventTime,
    event: e.EventName,
    service: e.EventSource?.replace(".amazonaws.com", ""),
    user: e.Username ?? r.userIdentity?.sessionContext?.sessionIssuer?.userName ?? r.userIdentity?.arn,
    identityType: r.userIdentity?.type,
    resources: (e.Resources ?? []).map((x) => x.ResourceName).filter(Boolean),
    sourceIp: r.sourceIPAddress,
    readOnly: r.readOnly ?? (e.ReadOnly === undefined ? undefined : e.ReadOnly === "true"),
    error: r.errorCode ? `${r.errorCode}${r.errorMessage ? `: ${r.errorMessage.slice(0, 160)}` : ""}` : undefined,
    request: params && params.length > 300 ? `${params.slice(0, 300)}…` : params,
  };
}

export type EventSummary = ReturnType<typeof summarizeEvent>;

/** AWS services acting on your behalf (autoscaling, CloudFormation internals...) — usually noise. */
export const isServiceEvent = (s: EventSummary) => s.identityType === "AWSService" || s.sourceIp?.endsWith(".amazonaws.com");

/** CloudTrail LookupEvents accepts exactly ONE lookup attribute — pick the most selective. */
export function chooseLookupAttribute(opts: { user?: string; eventSource?: string; resourceName?: string }): LookupAttribute {
  if (opts.resourceName) return { AttributeKey: "ResourceName", AttributeValue: opts.resourceName };
  if (opts.user) return { AttributeKey: "Username", AttributeValue: opts.user };
  if (opts.eventSource) {
    const src = opts.eventSource.includes(".") ? opts.eventSource : `${opts.eventSource}.amazonaws.com`;
    return { AttributeKey: "EventSource", AttributeValue: src };
  }
  return { AttributeKey: "ReadOnly", AttributeValue: "false" };
}

/** Top-N counts, e.g. who made the most changes. */
export function topCounts(values: (string | undefined)[], n = 10): { name: string; count: number }[] {
  const counts = new Map<string, number>();
  for (const v of values) if (v) counts.set(v, (counts.get(v) ?? 0) + 1);
  return [...counts.entries()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, n)
    .map(([name, count]) => ({ name, count }));
}
