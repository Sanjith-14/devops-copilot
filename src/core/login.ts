import { createInterface } from "node:readline/promises";
import { readFileSync, writeFileSync, existsSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { homedir } from "node:os";
import { loadSharedConfigFiles } from "@smithy/shared-ini-file-loader";

/**
 * `devops-copilot login` — terminal login helper. Two modes:
 *
 *  - session: exchange a profile's long-lived keys for temporary session
 *    credentials (STS GetSessionToken, with MFA if a device is configured or
 *    auto-detected) saved as the "copilot-session" profile.
 *  - role (--role-arn, or a profile with role_arn): assume the role — MFA
 *    device auto-detected, code asked only if needed — and save the role
 *    credentials as "copilot-<role-name>".
 *
 * Either way the user types at most a 6-digit code, never a password, and the
 * server discovers the written profile like any other.
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

export interface LoginArgs {
  profile: string;
  durationSeconds: number;
  roleArn?: string;
  mfaSerial?: string;
  /** Profile name to write role credentials to (default copilot-<role-name>). */
  name?: string;
  externalId?: string;
}

/** Pure — unit-tested. */
export function parseLoginArgs(argv: string[]): LoginArgs {
  const out: LoginArgs = { profile: "default", durationSeconds: 0 };
  let hours: number | undefined;
  for (let i = 0; i < argv.length; i++) {
    const next = () => argv[++i];
    switch (argv[i]) {
      case "--profile":
        out.profile = next();
        break;
      case "--duration-hours":
        hours = Number(next());
        break;
      case "--role-arn":
        out.roleArn = next();
        break;
      case "--mfa-serial":
        out.mfaSerial = next();
        break;
      case "--name":
        out.name = next();
        break;
      case "--external-id":
        out.externalId = next();
        break;
      default:
        throw new Error(`Unknown option "${argv[i]}". Usage: devops-copilot login --profile <name> [--role-arn <arn>] [--mfa-serial <arn>] [--name <profile>] [--duration-hours <n>]`);
    }
  }
  if (hours !== undefined && !(hours > 0)) throw new Error("--duration-hours must be a positive number");
  // Defaults: 8h MFA session; 1h for roles (the common role maximum).
  out.durationSeconds = Math.round((hours ?? (out.roleArn ? 1 : 8)) * 3600);
  return out;
}

/** "arn:aws:iam::123:role/path/ReadOnly" -> "copilot-ReadOnly". */
export const roleProfileName = (roleArn: string) =>
  `copilot-${roleArn.split("/").pop() ?? "role"}`.replace(/[^\w.-]/g, "-");

async function ask(question: string): Promise<string> {
  const rl = createInterface({ input: process.stdin, output: process.stdout });
  try {
    return (await rl.question(question)).trim();
  } finally {
    rl.close();
  }
}

function saveProfile(name: string, c: { accessKeyId: string; secretAccessKey: string; sessionToken?: string }, region: string): void {
  const awsDir = join(homedir(), ".aws");
  mkdirSync(awsDir, { recursive: true });
  const credsPath = join(awsDir, "credentials");
  const existing = existsSync(credsPath) ? readFileSync(credsPath, "utf-8") : "";
  const body = [
    `aws_access_key_id = ${c.accessKeyId}`,
    `aws_secret_access_key = ${c.secretAccessKey}`,
    ...(c.sessionToken ? [`aws_session_token = ${c.sessionToken}`] : []),
    `region = ${region}`,
  ].join("\n");
  writeFileSync(credsPath, upsertIniSection(existing, name, body), { mode: 0o600 });
}

export async function runLogin(argv: string[]): Promise<void> {
  const args = parseLoginArgs(argv);
  const { profile } = args;

  const { configFile, credentialsFile } = await loadSharedConfigFiles();
  const sectionOf = (name: string) => ({ ...(credentialsFile?.[name] ?? {}), ...(configFile?.[name] ?? {}) });
  const section = sectionOf(profile);
  if (Object.keys(section).length === 0) {
    const known = new Set([...Object.keys(configFile ?? {}), ...Object.keys(credentialsFile ?? {})]);
    throw new Error(`Profile "${profile}" not found in ~/.aws. Known: ${[...known].join(", ")}`);
  }
  if (section.sso_session || section.sso_start_url) {
    throw new Error(`Profile "${profile}" is an SSO profile — use \`aws sso login --profile ${profile}\` instead.`);
  }

  const region = section.region ?? process.env.AWS_REGION ?? "us-east-1";
  const [{ STSClient, GetSessionTokenCommand }, { fromIni }, mfa] = await Promise.all([
    import("@aws-sdk/client-sts"),
    import("@aws-sdk/credential-providers"),
    import("./mfa.js"),
  ]);
  const getCode = (serial: string, purpose: string) => ask(`Enter MFA code for ${serial} (${purpose}): `);

  // ── Role mode: --role-arn, or a profile that itself has role_arn ──────────
  const roleArn = args.roleArn ?? section.role_arn;
  if (roleArn) {
    const sourceProfile = args.roleArn ? profile : section.source_profile;
    if (!sourceProfile) {
      throw new Error(`Profile "${profile}" has role_arn but no source_profile; pass --role-arn with a profile that has keys.`);
    }
    const sourceCredentials = fromIni({ profile: sourceProfile });
    const configuredSerial = args.mfaSerial ?? section.mfa_serial ?? sectionOf(sourceProfile).mfa_serial;
    const detection = await mfa.detectMfaSerial(sourceCredentials, region, { configuredSerial });
    console.log(`Signed in as ${detection.caller.arn}`);
    console.log(detection.serial ? `MFA device: ${detection.serial} (${detection.source})` : `MFA device: none${detection.note ? ` — ${detection.note}` : ""}`);

    const result = await mfa.assumeRoleWithMfa({
      sourceCredentials,
      roleArn,
      region,
      serial: detection.serial,
      mfaRequired: Boolean(configuredSerial),
      getCode,
      sessionName: `devops-copilot-${(detection.caller.name ?? "user").slice(0, 40)}`.replace(/[^\w+=,.@-]/g, "-"),
      roleDurationSeconds: args.durationSeconds,
      mfaSessionDurationSeconds: 900, // only needed to mint the role creds once
      externalId: args.externalId,
    });
    const name = args.name ?? roleProfileName(roleArn);
    saveProfile(name, result.credentials, region);
    console.log(
      `Role credentials saved as profile "${name}" (${roleArn}${result.mfaUsed ? ", MFA verified" : ", MFA not required"}).\n` +
        `Expires: ${result.credentials.expiration?.toISOString()}\n` +
        `Use it: DEVOPS_COPILOT_PROFILES=${name}  (or aws ... --profile ${name})`,
    );
    return;
  }

  // ── Session mode: GetSessionToken (+ MFA if a device is known/detected) ───
  let mfaSerial: string | undefined = args.mfaSerial ?? section.mfa_serial;
  if (!mfaSerial) {
    const detection = await mfa.detectMfaSerial(fromIni({ profile }), region).catch(() => undefined);
    if (detection?.serial) {
      mfaSerial = detection.serial;
      console.log(`Detected MFA device ${mfaSerial} (${detection.source}). Tip: save it with \`aws configure set mfa_serial ${mfaSerial} --profile ${profile}\``);
    }
  }
  const tokenCode = mfaSerial ? mfa.validateMfaCode(await getCode(mfaSerial, "start session")) : undefined;

  const sts = new STSClient({ region, credentials: fromIni({ profile }) });
  const res = await sts.send(
    new GetSessionTokenCommand({
      DurationSeconds: args.durationSeconds,
      ...(mfaSerial ? { SerialNumber: mfaSerial, TokenCode: tokenCode } : {}),
    }),
  );
  const c = res.Credentials;
  if (!c?.AccessKeyId || !c.SecretAccessKey || !c.SessionToken) {
    throw new Error("STS returned no credentials");
  }
  saveProfile(SESSION_PROFILE, { accessKeyId: c.AccessKeyId, secretAccessKey: c.SecretAccessKey, sessionToken: c.SessionToken }, region);

  console.log(
    `Session credentials saved as profile "${SESSION_PROFILE}" (source: ${profile}${mfaSerial ? " + MFA" : ""}).\n` +
      `Expires: ${c.Expiration?.toISOString()}\n` +
      `The server will discover it automatically; pin it with DEVOPS_COPILOT_PROFILES=${SESSION_PROFILE}.\n` +
      `To assume a role from this session: devops-copilot login --profile ${SESSION_PROFILE} --role-arn <arn>`,
  );
}
