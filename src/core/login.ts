import { createInterface } from "node:readline/promises";
import { awsPaths, loadAwsFiles, profileSection, writeIniSection } from "./aws-files.js";

export { upsertIniSection } from "./aws-files.js";

/**
 * `awscm login` — MFA session for IAM users whose policy denies
 * everything until MFA is used. Exchanges the profile's long-lived keys for
 * temporary session credentials (STS GetSessionToken + 6-digit code) and
 * saves them as the "copilot-session" profile. The MFA device is detected
 * automatically if `mfa_serial` isn't configured.
 *
 * Roles are handled by `awscm role ...` (see roles.ts), which reuses
 * this same cached session, so after `login` switching roles needs no code.
 *
 * SSO users don't need this: `aws sso login --profile <x>` is the login.
 * Runs BEFORE the MCP server starts (separate invocation), so prompting on
 * stdin is safe — the JSON-RPC stream only owns stdio in serve mode.
 */

export const SESSION_PROFILE = "copilot-session";

export interface LoginArgs {
  profile: string;
  durationSeconds: number;
  mfaSerial?: string;
}

/** Pure — unit-tested. */
export function parseLoginArgs(argv: string[], env: NodeJS.ProcessEnv = process.env): LoginArgs {
  const out: LoginArgs = { profile: env.AWS_PROFILE ?? "default", durationSeconds: 12 * 3600 };
  for (let i = 0; i < argv.length; i++) {
    const next = () => argv[++i];
    if (argv[i] === "--profile") out.profile = next();
    else if (argv[i] === "--mfa-serial") out.mfaSerial = next();
    else if (argv[i] === "--duration-hours") {
      const h = Number(next());
      if (!(h > 0)) throw new Error("--duration-hours must be a positive number");
      out.durationSeconds = Math.round(h * 3600);
    } else {
      throw new Error(`Unknown option "${argv[i]}". Usage: awscm login [--profile <name>] [--duration-hours <n>] [--mfa-serial <arn>]`);
    }
  }
  return out;
}

export async function ask(question: string): Promise<string> {
  const rl = createInterface({ input: process.stdin, output: process.stdout });
  try {
    return (await rl.question(question)).trim();
  } finally {
    rl.close();
  }
}

/** Save an MFA session so `role use` (CLI and server) can reuse it without a new code. */
export function saveMfaSession(
  sourceProfile: string,
  c: { accessKeyId: string; secretAccessKey: string; sessionToken?: string; expiration?: Date },
  region: string,
): void {
  writeIniSection(awsPaths().credentials, SESSION_PROFILE, {
    aws_access_key_id: c.accessKeyId,
    aws_secret_access_key: c.secretAccessKey,
    aws_session_token: c.sessionToken,
    region,
    copilot_source_profile: sourceProfile,
    copilot_expiration: c.expiration?.toISOString(),
  });
}

export async function runLogin(argv: string[]): Promise<void> {
  const args = parseLoginArgs(argv);
  const files = await loadAwsFiles();
  const section = profileSection(files, args.profile);
  if (Object.keys(section).length === 0) {
    const known = new Set([...Object.keys(files.config), ...Object.keys(files.credentials)]);
    throw new Error(`Profile "${args.profile}" not found in ~/.aws. Known: ${[...known].join(", ")}`);
  }
  if (section.sso_session || section.sso_start_url) {
    throw new Error(`Profile "${args.profile}" is an SSO profile — use \`aws sso login --profile ${args.profile}\` instead.`);
  }
  if (section.role_arn) {
    throw new Error(`Profile "${args.profile}" is a role — switch to it with \`awscm role use ${args.profile}\`.`);
  }

  const region = section.region ?? process.env.AWS_REGION ?? "us-east-1";
  const [{ STSClient, GetSessionTokenCommand }, { fromIni }, mfa] = await Promise.all([
    import("@aws-sdk/client-sts"),
    import("@aws-sdk/credential-providers"),
    import("./mfa.js"),
  ]);
  const credentials = fromIni({ profile: args.profile, ignoreCache: true });

  let serial = args.mfaSerial ?? section.mfa_serial;
  if (!serial) {
    const d = await mfa.detectMfaSerial(credentials, region).catch(() => undefined);
    serial = d?.serial;
    if (serial) console.log(`MFA device: ${serial}${d?.source === "guess" ? " (guessed)" : ""}`);
  }
  const tokenCode = serial ? mfa.validateMfaCode(await ask("MFA code: ")) : undefined;

  const res = await new STSClient({ region, credentials }).send(
    new GetSessionTokenCommand({
      DurationSeconds: args.durationSeconds,
      ...(serial ? { SerialNumber: serial, TokenCode: tokenCode } : {}),
    }),
  );
  const c = res.Credentials;
  if (!c?.AccessKeyId || !c.SecretAccessKey || !c.SessionToken) throw new Error("STS returned no credentials");
  saveMfaSession(args.profile, { accessKeyId: c.AccessKeyId, secretAccessKey: c.SecretAccessKey, sessionToken: c.SessionToken, expiration: c.Expiration }, region);

  console.log(
    `✔ Logged in (${args.profile}${serial ? " + MFA" : ""}) until ${c.Expiration?.toLocaleString()}.\n` +
      `  Profile: ${SESSION_PROFILE}. Roles: awscm role use <name> (no code needed until then).`,
  );
}
