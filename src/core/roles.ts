import type { AwsCredentialIdentity } from "@aws-sdk/types";
import { awsPaths, loadAwsFiles, profileSection, writeIniSection, type AwsFiles } from "./aws-files.js";
import { assumeRoleWithMfa, detectMfaSerial, type CodePrompt, type MfaDeps } from "./mfa.js";
import { SESSION_PROFILE, ask, saveMfaSession } from "./login.js";

/**
 * Roles in two commands:
 *
 *   awscm role add prod-ro arn:aws:iam::123456789012:role/ReadOnly
 *   awscm role use prod-ro
 *
 * `add` writes a standard AWS CLI role profile ([profile prod-ro] with
 * role_arn / source_profile / mfa_serial — the MFA device is looked up once
 * and saved). `use` assumes it, asking for a 6-digit code only if needed,
 * and caches the MFA session for 12h so switching between roles that day
 * needs no further codes. The active role's credentials go to the fixed
 * profile "copilot-active", which the MCP server hot-reloads — switching
 * in a terminal changes what the copilot uses on its next request.
 */

export const ACTIVE_PROFILE = "copilot-active";
const RESERVED = new Set([ACTIVE_PROFILE, SESSION_PROFILE, "default"]);
const MFA_SESSION_SECONDS = 12 * 3600;

/** Pure: a still-valid MFA session minted from `sourceProfile`, if one is cached. */
export function cachedMfaSession(files: AwsFiles, sourceProfile: string, now = Date.now()): AwsCredentialIdentity | undefined {
  const s = files.credentials[SESSION_PROFILE];
  if (!s?.aws_access_key_id || !s.aws_secret_access_key || !s.aws_session_token) return undefined;
  if (s.copilot_source_profile !== sourceProfile) return undefined;
  const exp = s.copilot_expiration ? new Date(s.copilot_expiration) : undefined;
  if (!exp || exp.getTime() - now < 5 * 60_000) return undefined;
  return { accessKeyId: s.aws_access_key_id, secretAccessKey: s.aws_secret_access_key, sessionToken: s.aws_session_token, expiration: exp };
}

/** Pure: is this profile a role we can assume ourselves? */
export const isRoleProfile = (s: Record<string, string | undefined>) => Boolean(s.role_arn && s.source_profile);

export interface RoleCredentials {
  credentials: AwsCredentialIdentity;
  roleArn: string;
  region: string;
  mfaUsed: boolean;
  usedCachedSession: boolean;
}

/**
 * Credentials for a configured role profile. Shared by `role use` (terminal
 * prompt) and the MCP server (elicitation prompt). Order: cached MFA session
 * (no code) -> source keys without MFA -> MFA (one code, session cached).
 */
export async function getRoleCredentials(
  name: string,
  opts: { getCode: CodePrompt; deps?: MfaDeps; files?: AwsFiles },
): Promise<RoleCredentials> {
  const files = opts.files ?? (await loadAwsFiles());
  const cfg = profileSection(files, name);
  if (!isRoleProfile(cfg)) {
    throw new Error(`"${name}" is not a configured role. Add it: awscm role add ${name} <role-arn>`);
  }
  const source = cfg.source_profile!;
  const region = cfg.region ?? profileSection(files, source).region ?? process.env.AWS_REGION ?? "us-east-1";
  const cached = cachedMfaSession(files, source);
  const { fromIni } = await import("@aws-sdk/credential-providers");

  const result = await assumeRoleWithMfa({
    sourceCredentials: cached ? async () => cached : fromIni({ profile: source, ignoreCache: true }),
    roleArn: cfg.role_arn!,
    region,
    serial: cfg.mfa_serial,
    getCode: opts.getCode,
    sessionName: `devops-copilot-${source}`.replace(/[^\w+=,.@-]/g, "-").slice(0, 64),
    roleDurationSeconds: Number(cfg.duration_seconds) || 3600,
    mfaSessionDurationSeconds: MFA_SESSION_SECONDS,
    externalId: cfg.external_id,
    deps: opts.deps,
  });
  if (result.mfaSession) saveMfaSession(source, result.mfaSession, region);
  return {
    credentials: result.credentials,
    roleArn: cfg.role_arn!,
    region,
    mfaUsed: result.mfaUsed,
    usedCachedSession: Boolean(cached),
  };
}

// ── CLI ─────────────────────────────────────────────────────────────────────

const USAGE = `Usage:
  awscm role add <name> <role-arn> [--profile <source>] [--mfa-serial <arn>] [--region <r>] [--duration-hours <n>] [--external-id <id>]
  awscm role use <name>        (alias: select)
  awscm role list`;

function flags(argv: string[]): { positional: string[]; opts: Record<string, string> } {
  const positional: string[] = [];
  const opts: Record<string, string> = {};
  for (let i = 0; i < argv.length; i++) {
    if (argv[i].startsWith("--")) {
      const key = argv[i].slice(2);
      const value = argv[i + 1];
      if (value === undefined || value.startsWith("--")) throw new Error(`Missing value for --${key}\n${USAGE}`);
      opts[key] = value;
      i++;
    } else positional.push(argv[i]);
  }
  return { positional, opts };
}

async function roleAdd(argv: string[]): Promise<void> {
  const { positional, opts } = flags(argv);
  const [name, roleArn] = positional;
  if (!name || !roleArn) throw new Error(USAGE);
  if (!/^arn:aws[\w-]*:iam::\d{12}:role\/.+/.test(roleArn)) throw new Error(`"${roleArn}" doesn't look like a role ARN (arn:aws:iam::<account>:role/<name>).`);
  if (RESERVED.has(name) || !/^[\w.-]+$/.test(name)) throw new Error(`"${name}" can't be used as a role name.`);

  const files = await loadAwsFiles();
  const existing = profileSection(files, name);
  if (Object.keys(existing).length && !existing.role_arn) {
    throw new Error(`Profile "${name}" already exists and is not a role profile — pick another name.`);
  }
  const source = opts.profile ?? process.env.AWS_PROFILE ?? "default";
  const src = profileSection(files, source);
  if (!Object.keys(src).length) throw new Error(`Source profile "${source}" not found — pass --profile <profile with your keys>.`);

  let serial: string | undefined = opts["mfa-serial"] ?? src.mfa_serial;
  if (!serial) {
    const { fromIni } = await import("@aws-sdk/credential-providers");
    const region = src.region ?? process.env.AWS_REGION ?? "us-east-1";
    const d = await detectMfaSerial(fromIni({ profile: source, ignoreCache: true }), region).catch(() => undefined);
    if (d?.source === "iam") serial = d.serial;
    else if (d?.source === "guess") {
      const answer = await ask(`MFA device (guessed) ${d.serial}\n  Enter to accept, paste the correct ARN, or type "none": `);
      serial = answer === "" ? d.serial : answer === "none" ? undefined : answer;
    }
  }
  const hours = opts["duration-hours"] ? Number(opts["duration-hours"]) : undefined;
  if (hours !== undefined && !(hours > 0)) throw new Error("--duration-hours must be a positive number");

  // Standard AWS CLI keys, so `aws ... --profile <name>` works too.
  writeIniSection(awsPaths().config, `profile ${name}`, {
    role_arn: roleArn,
    source_profile: source,
    mfa_serial: serial,
    region: opts.region,
    duration_seconds: hours ? String(Math.round(hours * 3600)) : undefined,
    external_id: opts["external-id"],
  });
  console.log(`✔ Saved role "${name}" → ${roleArn}\n  source: ${source}${serial ? `, MFA: ${serial}` : ", no MFA device"}\n  Switch to it: awscm role use ${name}`);
}

async function roleUse(argv: string[]): Promise<void> {
  const name = argv[0];
  if (!name) throw new Error(USAGE);
  const r = await getRoleCredentials(name, { getCode: () => ask("MFA code: ") });
  writeIniSection(awsPaths().credentials, ACTIVE_PROFILE, {
    aws_access_key_id: r.credentials.accessKeyId,
    aws_secret_access_key: r.credentials.secretAccessKey,
    aws_session_token: r.credentials.sessionToken,
    region: r.region,
    copilot_role: name,
    copilot_role_arn: r.roleArn,
    copilot_expiration: r.credentials.expiration?.toISOString(),
  });
  const how = r.usedCachedSession ? "reused today's MFA session" : r.mfaUsed ? "MFA verified" : "no MFA needed";
  console.log(
    `✔ Now using "${name}" (${r.roleArn}) until ${r.credentials.expiration?.toLocaleTimeString() ?? "?"} — ${how}.\n` +
      `  The copilot picks it up automatically (profile ${ACTIVE_PROFILE}); CLI: aws ... --profile ${ACTIVE_PROFILE}`,
  );
}

/** Pure: rows for `role list`. */
export function roleRows(files: AwsFiles, now = Date.now()) {
  const active = files.credentials[ACTIVE_PROFILE];
  const activeValid = active?.copilot_expiration ? new Date(active.copilot_expiration).getTime() > now : false;
  return Object.keys(files.config)
    .filter((n) => isRoleProfile(profileSection(files, n)))
    .sort()
    .map((n) => {
      const s = profileSection(files, n);
      return {
        name: n,
        active: active?.copilot_role === n && activeValid,
        roleArn: s.role_arn!,
        source: s.source_profile!,
        mfa: Boolean(s.mfa_serial),
        mfaSessionValid: Boolean(cachedMfaSession(files, s.source_profile!, now)),
      };
    });
}

async function roleList(): Promise<void> {
  const files = await loadAwsFiles();
  const rows = roleRows(files);
  if (!rows.length) {
    console.log("No roles yet. Add one: awscm role add <name> <role-arn>");
    return;
  }
  for (const r of rows) {
    console.log(`${r.active ? "*" : " "} ${r.name.padEnd(20)} ${r.roleArn}  (via ${r.source}${r.mfa ? ", MFA" : ""}${r.mfa && r.mfaSessionValid ? " — session valid, no code needed" : ""})`);
  }
  const active = files.credentials[ACTIVE_PROFILE];
  if (active?.copilot_expiration) {
    const exp = new Date(active.copilot_expiration);
    console.log(`\nActive: ${active.copilot_role} ${exp.getTime() > Date.now() ? `until ${exp.toLocaleTimeString()}` : "(expired — run role use again)"}`);
  }
}

export async function runRole(argv: string[]): Promise<void> {
  const [cmd, ...rest] = argv;
  if (cmd === "add") return roleAdd(rest);
  if (cmd === "use" || cmd === "select") return roleUse(rest);
  if (cmd === "list" || cmd === "ls" || cmd === undefined) return roleList();
  throw new Error(USAGE);
}
