import {
  ResourceGroupsTaggingAPIClient,
  GetResourcesCommand,
  type ResourceTagMapping,
} from "@aws-sdk/client-resource-groups-tagging-api";
import { z } from "zod";
import type { ToolDefinition, ToolContext } from "../../core/types.js";
import type { AwsClientFactory } from "../../core/aws-client.js";
import { topCounts } from "../cloudtrail/events.js";

const MAX_PAGES = 20; // 100 per page -> 2,000 resources

/** "arn:aws:ec2:ap-south-1:123:instance/i-1" -> "ec2:instance"; "arn:aws:s3:::bucket" -> "s3". */
export function resourceType(arn: string): string {
  const parts = arn.split(":");
  const service = parts[2];
  const rest = parts.slice(5).join(":");
  const sub = rest.includes("/") ? rest.split("/")[0] : rest.includes(":") ? rest.split(":")[0] : "";
  return sub && service !== "s3" ? `${service}:${sub}` : service;
}

/** Which required tag keys (case-insensitive) a resource is missing. Pure. */
export function missingTags(mapping: ResourceTagMapping, required: string[]): string[] {
  const have = new Set((mapping.Tags ?? []).filter((t) => t.Value?.trim()).map((t) => t.Key!.toLowerCase()));
  return required.filter((k) => !have.has(k.toLowerCase()));
}

export function buildTaggingTools(factory: AwsClientFactory): ToolDefinition[] {
  const tagging = (ctx: ToolContext) => factory.getClient(ResourceGroupsTaggingAPIClient, ctx.accountId, ctx.region).client;

  return [
    {
      name: "find_untagged",
      description:
        "Tag compliance: find resources missing required tags (default Owner, Environment) across most AWS " +
        "services in one region, grouped by resource type. Empty-value tags count as missing. Use it for cost " +
        "allocation and ownership audits. Note: the Tagging API only sees resources that have (or once had) a " +
        "tag — never-tagged resources of some types may not appear.",
      risk: "read",
      inputSchema: {
        requiredTags: z.array(z.string().max(128)).min(1).max(20).optional().describe("Tag keys every resource must have (default ['Owner','Environment'])"),
        resourceTypes: z
          .array(z.string().max(64))
          .max(20)
          .optional()
          .describe("Limit to these types, e.g. ['ec2:instance','s3','rds:db','lambda:function']"),
      },
      handler: async (args, ctx) => {
        const required = (args.requiredTags as string[] | undefined) ?? ["Owner", "Environment"];
        const all: ResourceTagMapping[] = [];
        let PaginationToken: string | undefined;
        let pages = 0;
        do {
          const res = await tagging(ctx).send(
            new GetResourcesCommand({
              ResourcesPerPage: 100,
              PaginationToken,
              ResourceTypeFilters: args.resourceTypes as string[] | undefined,
            }),
          );
          all.push(...(res.ResourceTagMappingList ?? []));
          PaginationToken = res.PaginationToken || undefined;
          pages++;
        } while (PaginationToken && pages < MAX_PAGES);

        const noncompliant = all
          .map((m) => ({ arn: m.ResourceARN!, type: resourceType(m.ResourceARN!), missing: missingTags(m, required) }))
          .filter((r) => r.missing.length > 0);

        return {
          requiredTags: required,
          resourcesScanned: all.length,
          moreAvailable: Boolean(PaginationToken) || undefined,
          noncompliant: noncompliant.length,
          compliancePct: all.length ? Math.round(((all.length - noncompliant.length) / all.length) * 100) : 100,
          byType: topCounts(noncompliant.map((r) => r.type), 25),
          resources: noncompliant.slice(0, 100),
          truncated: noncompliant.length > 100 || undefined,
        };
      },
    },
  ];
}
