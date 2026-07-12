#!/usr/bin/env node
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
async function main(): Promise<void> {
  const cfg = loadConfig();
  const factory = new AwsClientFactory(cfg);
  await factory.discoverAccounts();
  const guardrails = new Guardrails(cfg);

  const server = new McpServer({ name: "devops-copilot", version: "0.1.0" });

  const modules = await discoverModules(cfg, factory);
  registerCoreTools(server, modules, factory);
  registerModules(server, modules, factory, guardrails);

  const totalTools = modules.reduce((n, m) => n + m.tools.length, 0) + 4;
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
