import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { AccountConfig, ToolContext, ToolDefinition, ToolResult } from "./types.js";
import type { AwsClientFactory } from "./aws-client.js";
import { GuardrailViolation } from "./guardrails.js";
import { TimeoutError, withTimeout } from "./helpers.js";
import { validateMfaCode } from "./mfa.js";

/**
 * Shared execution path for every service tool (direct calls and
 * run_across_accounts): resolve credentials (may prompt for MFA — not
 * counted against the timeout) -> run handler under a timeout.
 */
export async function executeTool(
  fullName: string,
  tool: ToolDefinition,
  args: Record<string, unknown>,
  account: AccountConfig,
  ctx: ToolContext,
  factory: AwsClientFactory,
  timeoutMs: number,
): Promise<ToolResult> {
  await factory.ensureCredentials(account);
  return withTimeout(tool.handler(args, ctx), timeoutMs, fullName);
}

export type AuditOutcome = "ok" | "error" | "denied" | "timeout";

export const outcomeOf = (err: unknown): AuditOutcome =>
  err instanceof GuardrailViolation ? "denied" : err instanceof TimeoutError ? "timeout" : "error";

/**
 * One JSON line per tool call on stderr (stdout belongs to MCP). Argument
 * NAMES only — values can contain resource names or filters users consider
 * sensitive. Pipe stderr to a file / log shipper for an audit trail.
 */
export function audit(entry: {
  tool: string;
  account?: string;
  region?: string;
  risk?: string;
  args?: Record<string, unknown>;
  ms: number;
  outcome: AuditOutcome;
  error?: unknown;
}): void {
  const { args, error, ...rest } = entry;
  console.error(
    JSON.stringify({
      audit: "tool_call",
      ts: new Date().toISOString(),
      ...rest,
      argNames: args ? Object.keys(args).filter((k) => args[k] !== undefined) : undefined,
      error: error ? String(error).split("\n")[0].slice(0, 200) : undefined,
    }),
  );
}

/**
 * Append a login instruction to credential-expiry errors so the LLM can tell
 * the user exactly what to run — instead of surfacing a bare SDK error.
 */
export function withLoginHint(message: string): string {
  if (/sso.*(expired|invalid|token)/i.test(message) || /SSOTokenProviderFailure/.test(message)) {
    return `${message}\nHint: the SSO session has expired — ask the user to run \`aws sso login --profile <profile>\` in a terminal, then retry.`;
  }
  if (/ExpiredToken|token.*expired|credentials.*expired/i.test(message)) {
    return `${message}\nHint: temporary credentials have expired — ask the user to re-run \`devops-copilot login --profile <profile>\` (or assume_role again), then retry.`;
  }
  return message;
}

export const canElicit = (server: McpServer) => Boolean(server.server.getClientCapabilities()?.elicitation);

/**
 * Ask the human user (via MCP elicitation — client UI, not the LLM) to
 * approve an action. Throws GuardrailViolation unless explicitly approved.
 */
export async function confirmWithUser(server: McpServer, message: string): Promise<void> {
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

/**
 * Ask the human for a 6-digit MFA code via elicitation. The code travels
 * client UI -> server only; it is never part of the LLM conversation, and it
 * is single-use and expires in ~30s, so it is not a reusable secret.
 */
export async function askMfaCode(server: McpServer, serial: string, purpose: string): Promise<string> {
  if (!canElicit(server)) {
    throw new GuardrailViolation(
      `An MFA code for ${serial} is needed to ${purpose}, but this MCP client cannot show prompts. ` +
        "Run `devops-copilot login --profile <name> [--role-arn <arn>]` in a terminal instead, then retry.",
    );
  }
  const res = await server.server.elicitInput({
    message:
      `MFA required to ${purpose}.\nEnter the current 6-digit code from your authenticator app for:\n${serial}\n` +
      "(Sent to the DevOps Copilot server only — the AI model never sees it.)",
    requestedSchema: {
      type: "object",
      properties: { code: { type: "string", title: "MFA code", description: "6 digits", minLength: 6, maxLength: 6 } },
      required: ["code"],
    },
  });
  if (res.action !== "accept") throw new GuardrailViolation("The user cancelled the MFA prompt.");
  return validateMfaCode((res.content as { code?: string } | undefined)?.code);
}
