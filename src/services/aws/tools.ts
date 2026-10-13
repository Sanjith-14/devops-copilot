import { z } from "zod";
import type { ToolDefinition } from "../../core/types.js";
import type { AwsClientFactory } from "../../core/aws-client.js";
import { assertReadAllowed, loadSdkCommand, shapeOutput } from "../../core/aws-ops.js";

/** Responses larger than this are cut; the LLM is told to narrow with `output`. */
const MAX_CHARS = 20_000;

/**
 * Generic read-only escape hatch: call ANY Describe/List/Get operation of any
 * installed AWS SDK client. The LLM builds the call from its own API
 * knowledge; code enforces read-only + secret denylist + redaction + size cap.
 */
export function buildAwsTools(factory: AwsClientFactory): ToolDefinition[] {
  return [
    {
      name: "read",
      description:
        "Generic read-only AWS API call for services without a dedicated tool. " +
        "Give the SDK service id and PascalCase operation (e.g. service 'ecs', operation 'DescribeClusters', " +
        "params { clusters: ['prod'] }). Only Describe*/List*/Get*/Search*/Lookup* operations are allowed; " +
        "secret-returning ones are blocked and secret-looking fields are redacted. " +
        "Use `output` (JMESPath) to keep large responses small. Prefer a dedicated tool when one exists.",
      risk: "read",
      inputSchema: {
        service: z
          .string()
          .max(64)
          .describe("AWS SDK v3 service id, as in @aws-sdk/client-<service>: ec2, ecs, eks, iam, route-53, elastic-load-balancing-v2, ..."),
        operation: z.string().max(128).describe("PascalCase API operation, e.g. DescribeClusters, ListRoles"),
        params: z.record(z.unknown()).optional().describe("Request parameters exactly as the API expects them"),
        output: z
          .string()
          .max(500)
          .optional()
          .describe("Optional JMESPath projection, e.g. \"clusters[].{name: clusterName, status: status}\""),
        limit: z.number().int().min(1).max(500).optional().describe("Max list items to return (default 50)"),
      },
      handler: async (args, ctx) => {
        const service = args.service as string;
        const operation = args.operation as string;
        assertReadAllowed(operation);

        const { Client, Command } = await loadSdkCommand(service, operation);
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const { client } = factory.getClient(Client as any, ctx.accountId, ctx.region);
        const res = await (client as { send(c: unknown): Promise<unknown> }).send(
          new Command((args.params as Record<string, unknown> | undefined) ?? {}),
        );

        const shaped = shapeOutput(res, {
          output: args.output as string | undefined,
          limit: args.limit as number | undefined,
        });
        const text = JSON.stringify(shaped);
        if (text.length <= MAX_CHARS) return { call: `${service}:${operation}`, ...shaped };
        return {
          call: `${service}:${operation}`,
          truncatedResponse: text.slice(0, MAX_CHARS),
          note: `Response was ${text.length} chars and was cut at ${MAX_CHARS}. Re-run with an \`output\` JMESPath projection or a smaller \`limit\`.`,
        };
      },
    },
  ];
}
