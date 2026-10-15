import { CloudTrailClient, LookupEventsCommand, type Event } from "@aws-sdk/client-cloudtrail";
import { z } from "zod";
import type { ToolDefinition, ToolContext } from "../../core/types.js";
import type { AwsClientFactory } from "../../core/aws-client.js";
import { chooseLookupAttribute, isServiceEvent, summarizeEvent, topCounts, type EventSummary } from "./events.js";

/** LookupEvents is throttled to ~2 req/s per account+region; cap the pages we pull. */
const MAX_PAGES = 6;

/**
 * CloudTrail "what changed?" tools — read-only, built on LookupEvents (the
 * last 90 days of management events, no trail setup required).
 */
export function buildCloudTrailTools(factory: AwsClientFactory): ToolDefinition[] {
  const ct = (ctx: ToolContext) => factory.getClient(CloudTrailClient, ctx.accountId, ctx.region).client;

  async function lookup(
    ctx: ToolContext,
    attr: ReturnType<typeof chooseLookupAttribute>,
    hours: number,
    keep: (s: EventSummary) => boolean,
    limit: number,
  ) {
    const end = new Date();
    const start = new Date(end.getTime() - hours * 3600_000);
    const kept: EventSummary[] = [];
    let NextToken: string | undefined;
    let pages = 0;
    let scanned = 0;
    do {
      const res = await ct(ctx).send(
        new LookupEventsCommand({ LookupAttributes: [attr], StartTime: start, EndTime: end, MaxResults: 50, NextToken }),
      );
      for (const e of (res.Events ?? []) as Event[]) {
        scanned++;
        const s = summarizeEvent(e);
        if (keep(s)) kept.push(s);
      }
      NextToken = res.NextToken;
      pages++;
    } while (NextToken && kept.length < limit && pages < MAX_PAGES);
    return {
      window: { start: start.toISOString(), end: end.toISOString() },
      scanned,
      events: kept.slice(0, limit),
      moreAvailable: Boolean(NextToken) || kept.length > limit || undefined,
    };
  }

  return [
    {
      name: "recent_changes",
      description:
        "Who changed what: recent WRITE (non-read-only) API activity from CloudTrail — e.g. 'what changed in the last " +
        "2 hours?', 'what did user X do today?', 'what changed in EC2?'. Returns events newest first plus top users " +
        "and actions. Includes failed attempts (AccessDenied etc.). Covers the last 90 days, per region " +
        "(IAM/global events are in us-east-1).",
      risk: "read",
      inputSchema: {
        hours: z.number().min(0.25).max(2160).optional().describe("Look-back window in hours (default 24)"),
        user: z.string().max(128).optional().describe("Only this IAM user / role session name"),
        eventSource: z.string().max(128).optional().describe("Only this service, e.g. 'ec2', 's3', 'iam'"),
        includeServiceEvents: z
          .boolean()
          .optional()
          .describe("Include actions AWS services performed on your behalf (default false — usually noise)"),
        limit: z.number().int().min(1).max(200).optional().describe("Max events (default 50)"),
      },
      handler: async (args, ctx) => {
        const user = args.user as string | undefined;
        const eventSource = args.eventSource as string | undefined;
        const src = eventSource && (eventSource.includes(".") ? eventSource : `${eventSource}.amazonaws.com`);
        const attr = chooseLookupAttribute({ user, eventSource });
        const keep = (s: EventSummary) =>
          s.readOnly !== true &&
          (!user || s.user === user) &&
          (!src || `${s.service}.amazonaws.com` === src) &&
          (Boolean(args.includeServiceEvents) || !isServiceEvent(s));

        const res = await lookup(ctx, attr, (args.hours as number | undefined) ?? 24, keep, (args.limit as number | undefined) ?? 50);
        return {
          ...res,
          count: res.events.length,
          failedAttempts: res.events.filter((e) => e.error).length,
          topUsers: topCounts(res.events.map((e) => e.user), 5),
          topActions: topCounts(res.events.map((e) => e.event), 10),
        };
      },
    },
    {
      name: "resource_history",
      description:
        "Change history of ONE resource from CloudTrail: every API call that touched it (by id or name — e.g. " +
        "sg-0abc, i-0abc, a bucket or function name), who made it, from which IP, and whether it failed. " +
        "Answers 'who modified this security group?'. Write events only unless includeReads is set.",
      risk: "read",
      inputSchema: {
        resourceName: z.string().max(256).describe("Resource id or name, e.g. sg-0abc123, my-bucket, arn:..."),
        hours: z.number().min(0.25).max(2160).optional().describe("Look-back window in hours (default 168 = 7 days)"),
        includeReads: z.boolean().optional().describe("Also include read-only calls (default false)"),
        limit: z.number().int().min(1).max(200).optional().describe("Max events (default 50)"),
      },
      handler: async (args, ctx) => {
        const attr = chooseLookupAttribute({ resourceName: args.resourceName as string });
        const keep = (s: EventSummary) => Boolean(args.includeReads) || s.readOnly !== true;
        const res = await lookup(ctx, attr, (args.hours as number | undefined) ?? 168, keep, (args.limit as number | undefined) ?? 50);
        return {
          resource: args.resourceName,
          ...res,
          count: res.events.length,
          lastChange: res.events[0],
          changedBy: topCounts(res.events.map((e) => e.user), 5),
        };
      },
    },
  ];
}
