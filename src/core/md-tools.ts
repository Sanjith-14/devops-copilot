import { readdirSync, readFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import { parse as parseYaml } from "yaml";
import { z } from "zod";
import type { RiskLevel, ToolDefinition } from "./types.js";
import type { AwsClientFactory } from "./aws-client.js";
import { assertReadAllowed, loadSdkCommand, shapeOutput } from "./aws-ops.js";

/**
 * Declarative tools: one `<tool>.tool.md` file = one MCP tool wrapping a single
 * AWS SDK operation. YAML frontmatter says WHAT to call; the markdown body is
 * the description the LLM reads. No TypeScript needed for simple
 * list/describe tools — multi-step logic still belongs in a module's tools.ts.
 *
 *   ---
 *   name: list_vpcs
 *   service: ec2              # -> @aws-sdk/client-ec2
 *   operation: DescribeVpcs   # -> DescribeVpcsCommand
 *   params:
 *     vpcIds: { type: "string[]", optional: true, mapsTo: VpcIds }
 *     state:  { type: string, optional: true, filter: state }   # EC2-style Filters
 *   fixed: { MaxResults: 100 }  # constant request fields
 *   output: "Vpcs[].{id: VpcId, cidr: CidrBlock}"   # JMESPath projection
 *   ---
 *   List VPCs with their CIDR ranges.
 */

const PARAM_TYPES = ["string", "number", "boolean", "string[]"] as const;

const paramSpec = z
  .object({
    type: z.enum(PARAM_TYPES),
    description: z.string().optional(),
    optional: z.boolean().optional(),
    enum: z.array(z.string()).optional(),
    /** Request field to set (default: the param name). */
    mapsTo: z.string().optional(),
    /** Send as an EC2-style filter: Filters: [{ Name: <filter>, Values: [...] }]. */
    filter: z.string().optional(),
  })
  .strict();

const toolSpec = z
  .object({
    name: z.string().regex(/^[a-z][a-z0-9_]*$/, "tool names are snake_case"),
    service: z.string().regex(/^[a-z0-9-]+$/),
    operation: z.string(),
    risk: z.enum(["read", "mutate", "destructive"]).default("read"),
    params: z.record(paramSpec).default({}),
    fixed: z.record(z.unknown()).default({}),
    output: z.string().optional(),
    limit: z.number().int().min(1).max(500).optional(),
  })
  .strict();

export type MdToolSpec = z.infer<typeof toolSpec> & { description: string };

/** Split `---\nyaml\n---\nbody` into its parts. */
function splitFrontmatter(text: string, file: string): { meta: unknown; body: string } {
  const m = /^---\r?\n([\s\S]*?)\r?\n---\r?\n?([\s\S]*)$/.exec(text);
  if (!m) throw new Error(`${file}: missing YAML frontmatter (--- ... ---)`);
  return { meta: parseYaml(m[1]) ?? {}, body: m[2].trim() };
}

/** Parse and validate one tool file. Throws with the file name on any problem. */
export function parseToolMarkdown(text: string, file = "<inline>"): MdToolSpec {
  const { meta, body } = splitFrontmatter(text, file);
  const parsed = toolSpec.safeParse(meta);
  if (!parsed.success) {
    const issues = parsed.error.issues.map((i) => `${i.path.join(".") || "(root)"}: ${i.message}`).join("; ");
    throw new Error(`${file}: invalid tool spec — ${issues}`);
  }
  if (body.length < 10) throw new Error(`${file}: the markdown body (tool description) is missing or too short`);

  const spec = { ...parsed.data, description: body };
  // A file can't label a write operation "read" to dodge the guardrails.
  if (spec.risk === "read") {
    try {
      assertReadAllowed(spec.operation);
    } catch (err) {
      throw new Error(`${file}: ${(err as Error).message}`);
    }
  }
  return spec;
}

/** zod input schema for the tool, generated from `params` (+ an optional `limit`). */
export function buildInputSchema(spec: MdToolSpec): z.ZodRawShape {
  const shape: z.ZodRawShape = {};
  for (const [name, p] of Object.entries(spec.params)) {
    let t: z.ZodTypeAny;
    if (p.enum) t = z.enum(p.enum as [string, ...string[]]);
    else if (p.type === "string") t = z.string().max(256);
    else if (p.type === "number") t = z.number();
    else if (p.type === "boolean") t = z.boolean();
    else t = z.array(z.string().max(256)).max(100);
    if (p.description) t = t.describe(p.description);
    shape[name] = p.optional ? t.optional() : t;
  }
  shape.limit = z.number().int().min(1).max(500).optional().describe("Max items to return (default 50)");
  return shape;
}

/** Map tool arguments onto the SDK request input. Pure — unit-testable. */
export function buildRequest(spec: MdToolSpec, args: Record<string, unknown>): Record<string, unknown> {
  const input: Record<string, unknown> = structuredClone(spec.fixed);
  const filters: { Name: string; Values: string[] }[] = [];
  for (const [name, p] of Object.entries(spec.params)) {
    const v = args[name];
    if (v === undefined) continue;
    if (p.filter) filters.push({ Name: p.filter, Values: Array.isArray(v) ? v.map(String) : [String(v)] });
    else input[p.mapsTo ?? name] = v;
  }
  if (filters.length) input.Filters = [...((input.Filters as typeof filters | undefined) ?? []), ...filters];
  return input;
}

export function buildMdTool(spec: MdToolSpec, factory: AwsClientFactory): ToolDefinition {
  return {
    name: spec.name,
    description: spec.description,
    risk: spec.risk as RiskLevel,
    inputSchema: buildInputSchema(spec),
    handler: async (args, ctx) => {
      const { Client, Command } = await loadSdkCommand(spec.service, spec.operation);
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const { client } = factory.getClient(Client as any, ctx.accountId, ctx.region);
      const res = await (client as { send(c: unknown): Promise<unknown> }).send(
        new Command(buildRequest(spec, args)),
      );
      return shapeOutput(res, { output: spec.output, limit: (args.limit as number | undefined) ?? spec.limit });
    },
  };
}

/**
 * Load every `*.tool.md` in a module folder. A broken file is logged and
 * skipped (the rest of the server still starts); SDK packages/operations are
 * resolved up front so typos fail at startup, not mid-conversation.
 */
export async function loadMarkdownTools(dir: string, factory: AwsClientFactory): Promise<ToolDefinition[]> {
  if (!existsSync(dir)) return [];
  const tools: ToolDefinition[] = [];
  for (const file of readdirSync(dir).filter((f) => f.endsWith(".tool.md")).sort()) {
    try {
      const spec = parseToolMarkdown(readFileSync(join(dir, file), "utf8"), file);
      await loadSdkCommand(spec.service, spec.operation);
      tools.push(buildMdTool(spec, factory));
    } catch (err) {
      console.error(`[registry] skipping markdown tool ${file}: ${(err as Error).message}`);
    }
  }
  return tools;
}

/**
 * Optional `module.md` for a markdown-only module (no index.ts):
 * frontmatter `health: { service, operation, params? }`, body = description.
 */
export function parseModuleMarkdown(
  text: string,
  file = "module.md",
): { description: string; health?: { service: string; operation: string; params?: Record<string, unknown> } } {
  const { meta, body } = splitFrontmatter(text, file);
  const health = (meta as { health?: { service: string; operation: string; params?: Record<string, unknown> } })
    .health;
  if (health) assertReadAllowed(health.operation);
  return { description: body, health };
}
