#!/usr/bin/env node
import { basename } from "node:path";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { loadConfig } from "./config.js";
import { AwsClientFactory } from "./aws-client.js";
import { Guardrails } from "./guardrails.js";
import { discoverModules, registerModules, registerCoreTools } from "./registry.js";

/**
 * DevOps Copilot — extensible multi-account MCP server for AWS.
 *
 * Boot sequence:
 *   env config -> discover ~/.aws profiles (accounts) -> guardrails (policy)
 *   -> discover service modules -> register tools -> stdio transport.
 *
 * NOTE: all logging goes to stderr (console.error). stdout is reserved
 * for the MCP protocol — writing logs there corrupts the JSON-RPC stream.
 */
const HELP = `awscm — DevOps Copilot helper (same binary as devops-copilot)

  awscm role add <name> <role-arn> [--profile <source>]   save a role (MFA device found automatically)
  awscm role use <name>                                   switch to it (alias: select); code only if needed
  awscm role list                                         roles, active one (*), MFA session status
  awscm login [--profile <name>]                          MFA session without a role (12h)

Run without arguments as "devops-copilot", it starts the MCP server (what Claude Desktop does).`;

/** Was the binary started under this name (e.g. the "awscm" bin link)? */
const invokedAs = (name: string) => basename(process.argv[1] ?? "").replace(/\.(c|m)?js$/, "") === name;

async function main(): Promise<void> {
  // Subcommand mode: `awscm login` / `awscm role ...` run terminal helpers
  // and exit — stdio is ours here, no MCP stream yet. (`awscm` and
  // `devops-copilot` are the same binary; MCP clients launch it bare.)
  const sub = process.argv[2];
  if (sub === "help" || sub === "--help" || sub === "-h" || (!sub && invokedAs("awscm"))) {
    console.log(HELP);
    return;
  }
  if (process.argv[2] === "login") {
    const { runLogin } = await import("./login.js");
    await runLogin(process.argv.slice(3));
    return;
  }
  // `awscm role add|use|list` — configure and switch IAM roles.
  if (process.argv[2] === "role") {
    const { runRole } = await import("./roles.js");
    await runRole(process.argv.slice(3));
    return;
  }

  const cfg = loadConfig();
  const factory = new AwsClientFactory(cfg);
  await factory.discoverAccounts();
  const guardrails = new Guardrails(cfg);

  const server = new McpServer({ name: "devops-copilot", version: "0.1.0" });

  const modules = await discoverModules(cfg, factory);
  registerCoreTools(server, modules, factory, cfg.toolTimeoutMs);
  registerModules(server, modules, factory, guardrails, cfg.toolTimeoutMs);

  const CORE_TOOLS = 7; // list_accounts, switch_account, list_assumable_roles, assume_role, list_modules, health_check, run_across_accounts
  const totalTools = modules.reduce((n, m) => n + m.tools.length, 0) + CORE_TOOLS;
  const accounts = factory.listAccounts();
  console.error(
    `[server] devops-copilot ready: ${modules.length} module(s), ${totalTools} tool(s), ` +
      `${accounts.length} account(s) [${accounts.map((a) => a.id).join(", ")}] ` +
      `default=${factory.defaultAccount()}, write=${cfg.allowWrite}, destructive=${cfg.allowDestructive}`,
  );

  const transport = new StdioServerTransport();
  await server.connect(transport);
}

main().catch((err) => {
  console.error("[server] fatal:", err);
  process.exit(1);
});
