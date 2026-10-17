import { readdirSync, existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { z } from "zod";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { ServiceModule, CopilotConfig, ToolContext, ToolDefinition } from "./types.js";
import { AwsClientFactory } from "./aws-client.js";
import { loadMarkdownTools, parseModuleMarkdown } from "./md-tools.js";
import { loadSdkCommand } from "./aws-ops.js";
import { Guardrails, GuardrailViolation } from "./guardrails.js";
import { askMfaCode, audit, canElicit, confirmWithUser, executeTool, outcomeOf, withLoginHint } from "./runner.js";
import { registerRoleTools } from "./role-tools.js";
import { registerPrompts } from "./prompts.js";

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
    const dir = join(servicesDir, entry.name);
    const modPath = join(dir, "index.js");
    const mdTools = await loadMarkdownTools(dir, factory);

    let mod: ServiceModule | undefined;
    if (existsSync(modPath)) {
      const imported = await import(modPath);
      const create = imported.default as ((f: AwsClientFactory) => ServiceModule) | undefined;
      mod = typeof create === "function" ? create(factory) : undefined;
      if (!mod?.name || !Array.isArray(mod.tools)) {
        console.error(`[registry] ${entry.name}/index.js does not default-export a ServiceModule, skipping`);
        continue;
      }
      mod.tools.push(...mdTools);
    } else if (mdTools.length > 0) {
      // Markdown-only module: no TypeScript at all.
      mod = markdownOnlyModule(entry.name, dir, mdTools, factory);
    } else {
      continue;
    }
    modules.push(mod);
    console.error(`[registry] loaded module "${mod.name}" (${mod.tools.length} tools)`);
  }
  return modules;
}

/** Build a ServiceModule for a folder that only contains `*.tool.md` (+ optional module.md). */
function markdownOnlyModule(
  name: string,
  dir: string,
  tools: ToolDefinition[],
  factory: AwsClientFactory,
): ServiceModule {
  const metaPath = join(dir, "module.md");
  const meta = existsSync(metaPath)
    ? parseModuleMarkdown(readFileSync(metaPath, "utf8"), `${name}/module.md`)
    : { description: `${name} (markdown tools)` };
  return {
    name,
    description: meta.description,
    tools,
    healthCheck: async (ctx) => {
      if (!meta.health) return { ok: true, detail: "no health check defined in module.md" };
      try {
        const { Client, Command } = await loadSdkCommand(meta.health.service, meta.health.operation);
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const { client } = factory.getClient(Client as any, ctx.accountId, ctx.region);
        await (client as { send(c: unknown): Promise<unknown> }).send(new Command(meta.health.params ?? {}));
        return { ok: true };
      } catch (err) {
        return { ok: false, detail: String(err) };
      }
    },
  };
}

/** Core-injected params: every service tool can target any account/region. */
const targetParams = {
  account: z.string().optional().describe("Account id from list_accounts. Omit to use the default account."),
  region: z.string().optional().describe("AWS region override. Omit to use the account/server default."),
};

const asText = (obj: unknown, isError = false) => ({
  content: [{ type: "text" as const, text: typeof obj === "string" ? obj : JSON.stringify(obj, null, 2) }],
  ...(isError ? { isError: true } : {}),
});

/**
 * Registers every tool from every module onto the MCP server, wrapping each
 * handler with: account/region resolution -> guardrail check -> credentials
 * (MFA prompt if needed) -> execution under a timeout -> account/region
 * tagging of the result -> one audit log line.
 */
export function registerModules(
  server: McpServer,
  modules: ServiceModule[],
  factory: AwsClientFactory,
  guardrails: Guardrails,
  timeoutMs = 30_000,
): void {
  for (const mod of modules) {
    for (const tool of mod.tools) {
      const fullName = `${mod.name}_${tool.name}`;

      server.registerTool(
        fullName,
        {
          description: `[${tool.risk.toUpperCase()}] ${tool.description}`,
          inputSchema: { ...tool.inputSchema, ...targetParams },
        },
        async (args: Record<string, unknown>) => {
          const started = Date.now();
          let ctx: ToolContext | undefined;
          try {
            await factory.refreshIfChanged(); // picks up `awscm role use` from a terminal
            const account = factory.resolveAccount(args.account as string | undefined);
            const region = factory.resolveRegion(account, args.region as string | undefined);
            ctx = { accountId: account.id, region };

            // Guardrails: the verdict may require the USER (not the LLM) to
            // approve this call, via an MCP elicitation request to the client.
            const { verdict, reason } = guardrails.decide(tool.risk, canElicit(server));
            if (verdict === "deny") throw new GuardrailViolation(reason ?? "Blocked by guardrails.");
            if (verdict === "confirm") {
              await confirmWithUser(
                server,
                `Approve ${tool.risk.toUpperCase()} operation "${fullName}" on account "${ctx.accountId}" (${ctx.region})?`,
              );
            }

            const result = await executeTool(fullName, tool, args, account, ctx, factory, timeoutMs);
            audit({ tool: fullName, account: ctx.accountId, region: ctx.region, risk: tool.risk, args, ms: Date.now() - started, outcome: "ok" });

            // Every response is tagged with its origin. Critical when results
            // from multiple accounts are merged into one LLM context.
            return asText({ _account: ctx.accountId, _region: ctx.region, ...result });
          } catch (err) {
            audit({
              tool: fullName,
              account: ctx?.accountId ?? (args.account as string | undefined),
              region: ctx?.region,
              risk: tool.risk,
              args,
              ms: Date.now() - started,
              outcome: outcomeOf(err),
              error: err,
            });
            const message = err instanceof GuardrailViolation ? err.message : `Error in ${fullName}: ${String(err)}`;
            return asText(withLoginHint(message), true);
          }
        },
      );
    }
  }
}

/** Max characters of one account's result inside run_across_accounts. */
const PER_ACCOUNT_CHARS = 8_000;

/** Core tools that exist regardless of which service modules are loaded. */
export function registerCoreTools(
  server: McpServer,
  modules: ServiceModule[],
  factory: AwsClientFactory,
  timeoutMs = 30_000,
): void {
  // MFA-protected ~/.aws profiles (role_arn + mfa_serial) prompt the user in
  // the client UI instead of failing.
  factory.setMfaCodeProvider((serial, purpose) => askMfaCode(server, serial, `use ${purpose}`));

  server.registerTool(
    "list_accounts",
    {
      description:
        "[READ] List usable AWS accounts: profiles auto-discovered from ~/.aws plus any roles assumed this session. Marks the default.",
      inputSchema: {},
    },
    async () => {
      await factory.refreshIfChanged();
      return asText(
        factory.listAccounts().map((a) => ({
          id: a.id,
          description: a.description ?? "",
          region: a.defaultRegion,
          default: a.id === factory.defaultAccount() || undefined,
        })),
      );
    },
  );

  server.registerTool(
    "switch_account",
    {
      description:
        "[READ] Switch which account/role every tool uses by default for the rest of this session, e.g. " +
        "'switch to prod-ro'. Works for any id from list_accounts, including role profiles added with " +
        "`awscm role add` — if the role needs MFA, the user is asked for the 6-digit code in a prompt " +
        "(only if needed; today's MFA session is reused). Returns the identity now in use.",
      inputSchema: { account: z.string().max(128).describe("Account id from list_accounts, e.g. 'prod-ro'") },
    },
    async (args: { account: string }) => {
      const started = Date.now();
      try {
        await factory.refreshIfChanged();
        const account = factory.resolveAccount(args.account);
        const region = factory.resolveRegion(account);
        await factory.ensureCredentials(account); // MFA prompt happens here, if needed
        const { STSClient, GetCallerIdentityCommand } = await import("@aws-sdk/client-sts");
        const id = await new STSClient({ region, credentials: factory.credentialsFor(account) }).send(new GetCallerIdentityCommand({}));
        const previous = factory.defaultAccount();
        factory.setDefaultAccount(account.id);
        audit({ tool: "switch_account", account: account.id, region, risk: "read", ms: Date.now() - started, outcome: "ok" });
        return asText({ switchedFrom: previous, nowUsing: account.id, identity: id.Arn, region, description: account.description });
      } catch (err) {
        audit({ tool: "switch_account", account: args.account, risk: "read", ms: Date.now() - started, outcome: outcomeOf(err), error: err });
        const message = err instanceof GuardrailViolation ? err.message : `Error in switch_account: ${String(err)}`;
        return asText(withLoginHint(message), true);
      }
    },
  );

  registerRoleTools(server, factory);

  server.registerTool(
    "list_modules",
    {
      description: "[READ] List loaded service modules and the tools each exposes, with risk levels.",
      inputSchema: {},
    },
    async () =>
      asText(
        modules.map((m) => ({
          module: m.name,
          description: m.description,
          tools: m.tools.map((t) => ({ name: `${m.name}_${t.name}`, risk: t.risk })),
        })),
      ),
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
      await factory.refreshIfChanged();
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
      return asText({ _account: ctx.accountId, _region: ctx.region, results });
    },
  );

  // Fan-out: one READ tool, many accounts, partial results.
  const toolIndex = new Map<string, ToolDefinition>();
  for (const m of modules) for (const t of m.tools) toolIndex.set(`${m.name}_${t.name}`, t);

  server.registerTool(
    "run_across_accounts",
    {
      description:
        "[READ] Run one READ-only tool against several (default: all) accounts in parallel and get every result " +
        "side by side, e.g. tool 'security_scorecard' or 'ec2_find_open_security_groups' across all accounts. " +
        "Accounts that fail (no permission, expired login) are reported individually; the rest still return.",
      inputSchema: {
        tool: z.string().max(128).describe("Full tool name, e.g. 's3_list_buckets' (see list_modules)"),
        args: z.record(z.unknown()).optional().describe("Arguments for that tool (without account)"),
        accounts: z.array(z.string()).max(50).optional().describe("Account ids from list_accounts. Omit for all."),
        region: z.string().optional().describe("Region for every account. Omit for each account's default."),
      },
    },
    async (input: { tool: string; args?: Record<string, unknown>; accounts?: string[]; region?: string }) => {
      const started = Date.now();
      try {
        await factory.refreshIfChanged();
        const tool = toolIndex.get(input.tool);
        if (!tool) {
          const near = [...toolIndex.keys()].filter((n) => n.includes(input.tool.split("_").pop() ?? "")).slice(0, 8);
          throw new Error(`Unknown tool "${input.tool}".${near.length ? ` Did you mean: ${near.join(", ")}?` : ""}`);
        }
        if (tool.risk !== "read") {
          throw new GuardrailViolation(`run_across_accounts only runs READ tools; "${input.tool}" is ${tool.risk.toUpperCase()}.`);
        }
        const targets = input.accounts ?? factory.listAccounts().map((a) => a.id);
        const args = { ...(input.args ?? {}) };
        delete args.account;

        // Resolve credentials one account at a time so MFA prompts don't stack up.
        const credErrors = new Map<string, unknown>();
        for (const id of targets) {
          try {
            await factory.ensureCredentials(factory.resolveAccount(id));
          } catch (err) {
            credErrors.set(id, err);
          }
        }

        const settled = await Promise.allSettled(
          targets.map(async (id) => {
            if (credErrors.has(id)) throw credErrors.get(id);
            const account = factory.resolveAccount(id);
            const ctx: ToolContext = { accountId: account.id, region: factory.resolveRegion(account, input.region) };
            return { ctx, result: await executeTool(input.tool, tool, args, account, ctx, factory, timeoutMs) };
          }),
        );

        const results = settled.map((s, i) => {
          if (s.status === "rejected") {
            return { account: targets[i], ok: false, error: withLoginHint(String(s.reason)).slice(0, 500) };
          }
          const json = JSON.stringify(s.value.result);
          return {
            account: targets[i],
            region: s.value.ctx.region,
            ok: true,
            ...(json.length > PER_ACCOUNT_CHARS
              ? { truncatedResult: json.slice(0, PER_ACCOUNT_CHARS), note: "result cut — call the tool directly for this account" }
              : { result: s.value.result }),
          };
        });
        const succeeded = results.filter((r) => r.ok).length;
        audit({ tool: `run_across_accounts:${input.tool}`, risk: "read", args, ms: Date.now() - started, outcome: succeeded ? "ok" : "error" });
        return asText({ tool: input.tool, accounts: targets.length, succeeded, failed: targets.length - succeeded, results });
      } catch (err) {
        audit({ tool: `run_across_accounts:${input.tool}`, risk: "read", ms: Date.now() - started, outcome: outcomeOf(err), error: err });
        const message = err instanceof GuardrailViolation ? err.message : `Error in run_across_accounts: ${String(err)}`;
        return asText(message, true);
      }
    },
  );

  registerPrompts(server, new Set(toolIndex.keys()));
}
