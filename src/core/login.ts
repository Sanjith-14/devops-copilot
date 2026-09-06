import { createInterface } from "node:readline/promises";
import { readFileSync, writeFileSync, existsSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { homedir } from "node:os";
import { loadSharedConfigFiles } from "@smithy/shared-ini-file-loader";

/**
 * `devops-copilot login` — terminal login helper for IAM users (optionally
 * with MFA). Exchanges a profile's long-lived keys for temporary session
 * credentials via STS GetSessionToken and saves them as the
 * "copilot-session" profile, which the server then discovers like any other.
 *
 * SSO users don't need this: `aws sso login --profile <x>` is the login, and
 * the SDK picks up the cached token automatically.
 *
 * This runs BEFORE the MCP server starts (separate invocation), so prompting
 * on stdin here is safe — the JSON-RPC stream only owns stdio in serve mode.
 */

export const SESSION_PROFILE = "copilot-session";

/** Replace (or append) one INI section in a credentials-file body. Pure, for tests. */
export function upsertIniSection(content: string, section: string, body: string): string {
  const block = `[${section}]\n${body.trim()}\n`;
  const pattern = new RegExp(`\\[${section}\\][^\\[]*`, "g");
  if (pattern.test(content)) return content.replace(pattern, block);
  const sep = content.length === 0 || content.endsWith("\n\n") ? "" : content.endsWith("\n") ? "\n" : "\n\n";
  return content + sep + block;
}

function parseArgs(argv: string[]): { profile: string; durationSeconds: number } {
  let profile = "default";
  let durationSeconds = 3600 * 8;
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === "--profile" && argv[i + 1]) profile = argv[++i];
    else if (argv[i] === "--duration-hours" && argv[i + 1]) durationSeconds = Number(argv[++i]) * 3600;
  }
  return { profile, durationSeconds };
}

export async function runLogin(argv: string[]): Promise<void> {
  const { profile, durationSeconds } = parseArgs(argv);

  const { configFile, credentialsFile } = await loadSharedConfigFiles();
  const section = { ...(credentialsFile?.[profile] ?? {}), ...(configFile?.[profile] ?? {}) };
  if (Object.keys(section).length === 0) {
    const known = new Set([...Object.keys(configFile ?? {}), ...Object.keys(credentialsFile ?? {})]);
    throw new Error(`Profile "${profile}" not found in ~/.aws. Known: ${[...known].join(", ")}`);
  }
  if (section.sso_session || section.sso_start_url) {
    throw new Error(`Profile "${profile}" is an SSO profile — use \`aws sso login --profile ${profile}\` instead.`);
  }

  const mfaSerial = section.mfa_serial;
  let tokenCode: string | undefined;
  if (mfaSerial) {
    const rl = createInterface({ input: process.stdin, output: process.stdout });
    tokenCode = (await rl.question(`Enter MFA code for ${mfaSerial}: `)).trim();
    rl.close();
  }

  const region = section.region ?? process.env.AWS_REGION ?? "us-east-1";
  const [{ STSClient, GetSessionTokenCommand }, { fromIni }] = await Promise.all([
    import("@aws-sdk/client-sts"),
    import("@aws-sdk/credential-providers"),
  ]);
  const sts = new STSClient({ region, credentials: fromIni({ profile }) });
  const res = await sts.send(
    new GetSessionTokenCommand({
      DurationSeconds: durationSeconds,
      ...(mfaSerial ? { SerialNumber: mfaSerial, TokenCode: tokenCode } : {}),
    }),
  );
  const c = res.Credentials;
  if (!c?.AccessKeyId || !c.SecretAccessKey || !c.SessionToken) {
    throw new Error("STS returned no credentials");
  }

  const awsDir = join(homedir(), ".aws");
  mkdirSync(awsDir, { recursive: true });
  const credsPath = join(awsDir, "credentials");
  const existing = existsSync(credsPath) ? readFileSync(credsPath, "utf-8") : "";
  const body = [
    `aws_access_key_id = ${c.AccessKeyId}`,
    `aws_secret_access_key = ${c.SecretAccessKey}`,
    `aws_session_token = ${c.SessionToken}`,
    `region = ${region}`,
  ].join("\n");
  writeFileSync(credsPath, upsertIniSection(existing, SESSION_PROFILE, body), { mode: 0o600 });

  console.log(
    `Session credentials saved as profile "${SESSION_PROFILE}" (source: ${profile}${mfaSerial ? " + MFA" : ""}).\n` +
      `Expires: ${c.Expiration?.toISOString()}\n` +
      `The server will discover it automatically; pin it with DEVOPS_COPILOT_PROFILES=${SESSION_PROFILE}.`,
  );
}
