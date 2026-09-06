import { readdirSync, existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { z } from "zod";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { ServiceModule, CopilotConfig, ToolContext } from "./types.js";
import { AwsClientFactory } from "./aws-client.js";
import { Guardrails, GuardrailViolation } from "./guardrails.js";

const __dirname = dirname(fileURLToPath(import.meta.url));

/**
 * Discovers service modules at runtime by scanning ../services/<name>/index.js.
 * Adding a new AWS service = adding one folder with a default-exported
 * ServiceModule. No core file is ever edited (open-closed principle).
 */
export async function discoverModules(cfg: CopilotConfig, factory: AwsClientFactory): Promise<ServiceModule[]> {
  const servicesDir = join(__dirname, "..", "services");
  if (!existsSync(servicesDir)) return [];

  const modules: ServiceModule[] = [];
  for (const entry of readdirSync(servicesDir, { withFileTypes: true })) {
    if (!entry.isDirectory()) continue;
    const enabled = cfg.enabledServices === "*" || cfg.enabledServices.includes(entry.name);
    if (!enabled) {
      console.error(`[registry] skipping disabled module "${entry.name}"`);
      continue;
    }
    const modPath = join(servicesDir, entry.name, "index.js");
    if (!existsSync(modPath)) continue;
    const imported = await import(modPath);
    const create = imported.default as ((f: AwsClientFactory) => ServiceModule) | undefined;
    const mod = typeof create === "function" ? create(factory) : undefined;
    if (!mod?.name || !Array.isArray(mod.tools)) {
      console.error(`[registry] ${entry.name}/index.js does not default-export a ServiceModule, skipping`);
      continue;
    }
    modules.push(mod);
    console.error(`[registry] loaded module "${mod.name}" (${mod.tools.length} tools)`);
  }
  return modules;
}

/**
 * Registers every tool from every module onto the MCP server, wrapping each
 * handler with: account/region resolution -> guardrail check -> execution ->
 * account/region tagging of the result.
 */
export function registerModules(
  server: McpServer,
  modules: ServiceModule[],
  factory: AwsClientFactory,
  guardrails: Guardrails,
): void {
  for (const mod of modules) {
    for (const tool of mod.tools) {
      const fullName = `${mod.name}_${tool.name}`;

      // Core injects account/region params into every tool so the LLM can
      // target any registered account. Modules never see this plumbing.
      const schema = {
        ...tool.inputSchema,
        account: z
          .string()
          .optional()
          .describe("Account id from list_accounts. Omit to use the default account."),
        region: z.string().optional().describe("AWS region override. Omit to use the account/server default."),
      };

      server.registerTool(
        fullName,
        {
          description: `[${tool.risk.toUpperCase()}] ${tool.description}`,
          inputSchema: schema,
        },
        async (args: Record<string, unknown>) => {
          try {
            const account = factory.resolveAccount(args.account as string | undefined);
            const region = factory.resolveRegion(account, args.region as string | undefined);
            const ctx: ToolContext = { accountId: account.id, region };

            // Guardrails: the verdict may require the USER (not the LLM) to
            // approve this call, via an MCP elicitation request to the client.
            const canConfirm = Boolean(server.server.getClientCapabilities()?.elicitation);
            const { verdict, reason } = guardrails.decide(tool.risk, canConfirm);
            if (verdict === "deny") throw new GuardrailViolation(reason ?? "Blocked by guardrails.");
            if (verdict === "confirm") {
              await confirmWithUser(
                server,
                `Approve ${tool.risk.toUpperCase()} operation "${fullName}" on account "${ctx.accountId}" (${ctx.region})?`,
              );
            }

            const result = await tool.handler(args, ctx);

            // Every response is tagged with its origin. Critical when results
            // from multiple accounts are merged into one LLM context.
            const tagged = { _account: ctx.accountId, _region: ctx.region, ...result };
            return { content: [{ type: "text" as const, text: JSON.stringify(tagged, null, 2) }] };
          } catch (err) {
            const message = err instanceof GuardrailViolation ? err.message : `Error in ${fullName}: ${String(err)}`;
            return { content: [{ type: "text" as const, text: withLoginHint(message) }], isError: true };
          }
        },
      );
    }
  }
}

/**
 * Append a login instruction to credential-expiry errors so the LLM can tell
 * the user exactly what to run — instead of surfacing a bare SDK error.
 */
function withLoginHint(message: string): string {
  if (/sso.*(expired|invalid|token)/i.test(message) || /SSOTokenProviderFailure/.test(message)) {
    return `${message}\nHint: the SSO session has expired — ask the user to run \`aws sso login --profile <profile>\` in a terminal, then retry.`;
  }
  if (/ExpiredToken|token.*expired|credentials.*expired/i.test(message)) {
    return `${message}\nHint: temporary credentials have expired — ask the user to re-run \`devops-copilot login --profile <profile>\` (or their usual AWS login) in a terminal, then retry.`;
  }
  return message;
}

/**
 * Ask the human user (via MCP elicitation — client UI, not the LLM) to
 * approve an action. Throws GuardrailViolation unless explicitly approved.
 */
async function confirmWithUser(server: McpServer, message: string): Promise<void> {
  const res = await server.server.elicitInput({
    message,
    requestedSchema: {
      type: "object",
      properties: { approve: { type: "boolean", title: "Approve this operation?" } },
      required: ["approve"],
    },
  });
  if (res.action !== "accept" || (res.content as { approve?: boolean } | undefined)?.approve !== true) {
    throw new GuardrailViolation("The user declined this operation.");
  }
}

/** Core tools that exist regardless of which service modules are loaded. */
export function registerCoreTools(server: McpServer, modules: ServiceModule[], factory: AwsClientFactory): void {
  server.registerTool(
    "list_accounts",
    {
      description:
        "[READ] List usable AWS accounts: profiles auto-discovered from ~/.aws plus any roles assumed this session. Marks the default.",
      inputSchema: {},
    },
    async () => ({
      content: [
        {
          type: "text" as const,
          text: JSON.stringify(
            factory.listAccounts().map((a) => ({
              id: a.id,
              description: a.description ?? "",
              region: a.defaultRegion,
              default: a.id === factory.defaultAccount() || undefined,
            })),
            null,
            2,
          ),
        },
      ],
    }),
  );

  server.registerTool(
    "assume_role",
    {
      description:
        "[READ] Assume an IAM role via STS and register it as a temporary account for this session (usable via the `account` parameter of every tool). Requires interactive user approval. Access is bounded by the role's trust policy — this cannot grant anything AWS itself would refuse.",
      inputSchema: {
        roleArn: z.string().max(2048).describe("ARN of the role to assume, e.g. arn:aws:iam::123456789012:role/ReadOnly"),
        label: z
          .string()
          .max(64)
          .describe("Short account id to register it under, e.g. 'prod-readonly'. Used as the `account` parameter."),
        sourceAccount: z
          .string()
          .optional()
          .describe("Existing account id whose credentials perform the AssumeRole call. Omit for the default account."),
        region: z.string().optional().describe("Default region for the new account. Omit to inherit."),
      },
    },
    async (args: { roleArn: string; label: string; sourceAccount?: string; region?: string }) => {
      try {
        if (!server.server.getClientCapabilities()?.elicitation) {
          throw new GuardrailViolation(
            "assume_role requires interactive user approval, but this MCP client does not support elicitation. " +
              "Add a profile with role_arn/source_profile to ~/.aws/config instead.",
          );
        }
        const source = factory.resolveAccount(args.sourceAccount);
        await confirmWithUser(
          server,
          `Assume IAM role ${args.roleArn} (as account "${args.label}") using credentials of "${source.id}"?`,
        );

        const { fromTemporaryCredentials } = await import("@aws-sdk/credential-providers");
        const region = args.region ?? factory.resolveRegion(source);
        const credentials = fromTemporaryCredentials({
          masterCredentials: factory.credentialsFor(source),
          params: { RoleArn: args.roleArn, RoleSessionName: "devops-copilot", DurationSeconds: 3600 },
          clientConfig: { region },
        });

        // Prove the role actually works before registering it.
        const { STSClient, GetCallerIdentityCommand } = await import("@aws-sdk/client-sts");
        const identity = await new STSClient({ region, credentials }).send(new GetCallerIdentityCommand({}));

        factory.registerEphemeralAccount(
          {
            id: args.label,
            profile: "",
            defaultRegion: region,
            description: `Assumed role ${args.roleArn} (session-scoped, via ${source.id})`,
          },
          credentials,
        );
        return {
          content: [
            {
              type: "text" as const,
              text: JSON.stringify(
                {
                  registered: args.label,
                  identity: { account: identity.Account, arn: identity.Arn },
                  note: "Session-scoped: gone when the server restarts. Use it via the `account` parameter.",
                },
                null,
                2,
              ),
            },
          ],
        };
      } catch (err) {
        const message = err instanceof GuardrailViolation ? err.message : `Error in assume_role: ${String(err)}`;
        return { content: [{ type: "text" as const, text: message }], isError: true };
      }
    },
  );

  server.registerTool(
    "list_modules",
    {
      description: "[READ] List loaded service modules and the tools each exposes, with risk levels.",
      inputSchema: {},
    },
    async () => ({
      content: [
        {
          type: "text" as const,
          text: JSON.stringify(
            modules.map((m) => ({
              module: m.name,
              description: m.description,
              tools: m.tools.map((t) => ({ name: `${m.name}_${t.name}`, risk: t.risk })),
            })),
            null,
            2,
          ),
        },
      ],
    }),
  );

  server.registerTool(
    "health_check",
    {
      description: "[READ] Run reachability checks for every loaded module against a given account.",
      inputSchema: {
        account: z.string().optional().describe("Account id to check. Omit for default."),
        region: z.string().optional().describe("Region override."),
      },
    },
    async (args: { account?: string; region?: string }) => {
      const account = factory.resolveAccount(args.account);
      const region = factory.resolveRegion(account, args.region);
      const ctx: ToolContext = { accountId: account.id, region };
      const results = await Promise.all(
        modules.map(async (m) => {
          try {
            const r = await m.healthCheck(ctx);
            return { module: m.name, ...r };
          } catch (err) {
            return { module: m.name, ok: false, detail: String(err) };
          }
        }),
      );
      return {
        content: [
          {
            type: "text" as const,
            text: JSON.stringify({ _account: ctx.accountId, _region: ctx.region, results }, null, 2),
          },
        ],
      };
    },
  );
}
