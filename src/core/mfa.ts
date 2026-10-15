import {
  STSClient,
  GetCallerIdentityCommand,
  GetSessionTokenCommand,
  AssumeRoleCommand,
  type Credentials,
} from "@aws-sdk/client-sts";
import { IAMClient, ListMFADevicesCommand } from "@aws-sdk/client-iam";
import type { AwsCredentialIdentity, AwsCredentialIdentityProvider } from "@aws-sdk/types";

/**
 * MFA-protected role assumption without passwords.
 *
 * The user only ever types a 6-digit TOTP code. Everything else is derived:
 *   1. who am I?            STS GetCallerIdentity  -> user ARN
 *   2. which MFA device?    IAM ListMFADevices (own user) -> serial ARN
 *   3. MFA session          STS GetSessionToken(serial, code)
 *   4. the role             STS AssumeRole(roleArn) using the MFA session
 *
 * Why two steps (3+4) instead of AssumeRole(SerialNumber, TokenCode) alone:
 * common "force MFA" IAM policies deny sts:AssumeRole to non-MFA callers, so
 * the AssumeRole call itself must come from an MFA session. It also lets us
 * refresh the role (default 1h) from the MFA session (default 12h) without
 * asking for another code.
 */

/** Asks the human for a TOTP code (terminal prompt or MCP elicitation). */
export type CodePrompt = (serial: string, purpose: string) => Promise<string>;

interface StsLike {
  send(command: unknown): Promise<any>; // eslint-disable-line @typescript-eslint/no-explicit-any
}
/** Injectable for tests. */
export interface MfaDeps {
  sts: (credentials: AwsCredentialIdentityProvider | AwsCredentialIdentity, region: string) => StsLike;
  iam: (credentials: AwsCredentialIdentityProvider | AwsCredentialIdentity, region: string) => StsLike;
}
const realDeps: MfaDeps = {
  sts: (credentials, region) => new STSClient({ region, credentials }),
  iam: (credentials, region) => new IAMClient({ region, credentials }),
};

export function validateMfaCode(code: string | undefined): string {
  const c = (code ?? "").replace(/\s+/g, "");
  if (!/^\d{6}$/.test(c)) throw new Error("MFA code must be exactly 6 digits.");
  return c;
}

export interface CallerInfo {
  arn: string;
  account: string;
  kind: "user" | "assumed-role" | "root" | "federated-user" | "other";
  /** IAM user name, or role name for assumed-role callers. */
  name?: string;
  /** For assumed-role callers: the underlying role ARN (what trust policies name). */
  roleArn?: string;
}

/** Pure: classify an STS caller ARN. */
export function parseCallerArn(arn: string): CallerInfo {
  const m = /^arn:aws[\w-]*:(iam|sts)::(\d{12}):(.+)$/.exec(arn);
  if (!m) return { arn, account: "", kind: "other" };
  const [, svc, account, rest] = m;
  if (rest === "root") return { arn, account, kind: "root" };
  if (svc === "iam" && rest.startsWith("user/")) return { arn, account, kind: "user", name: rest.split("/").pop() };
  if (svc === "sts" && rest.startsWith("assumed-role/")) {
    const role = rest.split("/")[1];
    return { arn, account, kind: "assumed-role", name: role, roleArn: `arn:aws:iam::${account}:role/${role}` };
  }
  if (svc === "sts" && rest.startsWith("federated-user/")) return { arn, account, kind: "federated-user", name: rest.split("/")[1] };
  return { arn, account, kind: "other" };
}

export interface MfaDetection {
  caller: CallerInfo;
  serial?: string;
  source: "configured" | "iam" | "guess" | "none";
  devices?: string[];
  note?: string;
}

/**
 * Find the caller's MFA device. Order: explicitly configured serial ->
 * IAM ListMFADevices on the caller's own user (allowed by standard
 * self-service MFA policies even before MFA) -> conventional
 * `mfa/<username>` guess if listing is denied.
 */
export async function detectMfaSerial(
  credentials: AwsCredentialIdentityProvider,
  region: string,
  opts: { configuredSerial?: string; deps?: MfaDeps } = {},
): Promise<MfaDetection> {
  const deps = opts.deps ?? realDeps;
  const id = await deps.sts(credentials, region).send(new GetCallerIdentityCommand({}));
  const caller = parseCallerArn(id.Arn as string);
  if (opts.configuredSerial) return { caller, serial: opts.configuredSerial, source: "configured" };
  if (caller.kind !== "user") {
    return { caller, source: "none", note: `caller is ${caller.kind}; MFA devices belong to IAM users — pass mfaSerial explicitly if needed` };
  }
  try {
    const res = await deps.iam(credentials, "us-east-1").send(new ListMFADevicesCommand({}));
    const devices = ((res.MFADevices ?? []) as { SerialNumber?: string }[]).map((d) => d.SerialNumber!).filter(Boolean);
    if (devices.length === 0) return { caller, source: "none", devices, note: "no MFA device registered for this user" };
    return {
      caller,
      serial: devices[0],
      source: "iam",
      devices,
      note: devices.length > 1 ? `${devices.length} devices found; using the first — pass mfaSerial to choose` : undefined,
    };
  } catch {
    return {
      caller,
      serial: `arn:aws:iam::${caller.account}:mfa/${caller.name}`,
      source: "guess",
      note: "iam:ListMFADevices was denied; guessed the conventional device name — set mfa_serial in ~/.aws/config if this is wrong",
    };
  }
}

const toIdentity = (c: Credentials | undefined): AwsCredentialIdentity => {
  if (!c?.AccessKeyId || !c.SecretAccessKey) throw new Error("STS returned no credentials");
  return { accessKeyId: c.AccessKeyId, secretAccessKey: c.SecretAccessKey, sessionToken: c.SessionToken, expiration: c.Expiration };
};

const isAccessDenied = (err: unknown) => /AccessDenied|not authorized/i.test(String(err));
const isBadCode = (err: unknown) => /MultiFactorAuthentication failed|invalid MFA|TokenCode/i.test(String(err));

export interface AssumeOptions {
  sourceCredentials: AwsCredentialIdentityProvider;
  roleArn: string;
  region: string;
  /** MFA device ARN. Used only if needed, unless mfaRequired is set. */
  serial?: string;
  /** Skip the no-MFA attempt (known requirement: profile mfa_serial or trust policy). */
  mfaRequired?: boolean;
  getCode?: CodePrompt;
  sessionName?: string;
  roleDurationSeconds?: number;
  /** Lifetime of the intermediate MFA session (refresh window). */
  mfaSessionDurationSeconds?: number;
  externalId?: string;
  deps?: MfaDeps;
}

export interface AssumeResult {
  credentials: AwsCredentialIdentity;
  /** MFA session used to mint (and later refresh) the role credentials. */
  mfaSession?: AwsCredentialIdentity;
  flow: "mfa-session-then-role" | "role-with-mfa" | "role";
  mfaUsed: boolean;
}

/** Assume a role, asking for an MFA code only when an MFA device applies. */
export async function assumeRoleWithMfa(o: AssumeOptions): Promise<AssumeResult> {
  const deps = o.deps ?? realDeps;
  const source = await o.sourceCredentials();
  const assumeInput = (extra: Record<string, unknown> = {}) =>
    new AssumeRoleCommand({
      RoleArn: o.roleArn,
      RoleSessionName: o.sessionName ?? "devops-copilot",
      DurationSeconds: o.roleDurationSeconds ?? 3600,
      ...(o.externalId ? { ExternalId: o.externalId } : {}),
      ...extra,
    });
  const ask = async (purpose: string) => {
    if (!o.getCode) throw new Error(`MFA code required for ${o.serial} but no way to prompt the user.`);
    return validateMfaCode(await o.getCode(o.serial!, purpose));
  };

  // MFA path. Long-term keys: MFA session first, then the role (works under
  // "force MFA" policies). Session credentials: one-step AssumeRole with MFA.
  const mfaFlow = async (): Promise<AssumeResult> => {
    if (source.sessionToken) {
      const code = await ask(`assume ${o.roleArn}`);
      const r = await deps.sts(source, o.region).send(assumeInput({ SerialNumber: o.serial, TokenCode: code }));
      return { credentials: toIdentity(r.Credentials), flow: "role-with-mfa", mfaUsed: true };
    }
    const code = await ask(`assume ${o.roleArn}`);
    let mfaSession: AwsCredentialIdentity;
    try {
      const s = await deps.sts(source, o.region).send(
        new GetSessionTokenCommand({ SerialNumber: o.serial, TokenCode: code, DurationSeconds: o.mfaSessionDurationSeconds ?? 12 * 3600 }),
      );
      mfaSession = toIdentity(s.Credentials);
    } catch (err) {
      if (isBadCode(err) || !isAccessDenied(err)) throw err;
      // GetSessionToken not permitted: one-step AssumeRole with MFA (TOTP codes are single-use, so ask again).
      const fresh = await ask(`assume ${o.roleArn} (one-step retry)`);
      const r = await deps.sts(source, o.region).send(assumeInput({ SerialNumber: o.serial, TokenCode: fresh }));
      return { credentials: toIdentity(r.Credentials), flow: "role-with-mfa", mfaUsed: true };
    }
    const r = await deps.sts(mfaSession, o.region).send(assumeInput());
    return { credentials: toIdentity(r.Credentials), mfaSession, flow: "mfa-session-then-role", mfaUsed: true };
  };

  // Known to need MFA (profile has mfa_serial, or the trust policy demands it): don't waste a call.
  if (o.serial && o.mfaRequired) return mfaFlow();

  // Otherwise "MFA only if needed": try without, fall back to MFA on AccessDenied.
  try {
    const r = await deps.sts(source, o.region).send(assumeInput());
    return { credentials: toIdentity(r.Credentials), flow: "role", mfaUsed: false };
  } catch (err) {
    if (isAccessDenied(err) && o.serial) return mfaFlow();
    throw new Error(
      `${String(err)}${isAccessDenied(err) ? "\nHint: the role's trust policy may require MFA, or this identity is not trusted by the role — pass mfaSerial if you use an MFA device." : ""}`,
    );
  }
}

const expiresSoon = (c?: AwsCredentialIdentity, marginMs = 5 * 60_000) =>
  !c || (c.expiration !== undefined && c.expiration.getTime() - Date.now() < marginMs);

/**
 * Credential provider for an MFA-assumed role that refreshes itself:
 * role creds are re-minted from the MFA session silently; only when the MFA
 * session itself expires is the user asked for a new code.
 */
export function refreshingRoleProvider(opts: AssumeOptions, initial: AssumeResult): AwsCredentialIdentityProvider {
  const deps = opts.deps ?? realDeps;
  let current = initial.credentials;
  let mfaSession = initial.mfaSession;
  let inflight: Promise<AwsCredentialIdentity> | undefined;

  const refresh = async (): Promise<AwsCredentialIdentity> => {
    if (mfaSession && !expiresSoon(mfaSession)) {
      const r = await deps.sts(mfaSession, opts.region).send(
        new AssumeRoleCommand({
          RoleArn: opts.roleArn,
          RoleSessionName: opts.sessionName ?? "devops-copilot",
          DurationSeconds: opts.roleDurationSeconds ?? 3600,
          ...(opts.externalId ? { ExternalId: opts.externalId } : {}),
        }),
      );
      return toIdentity(r.Credentials);
    }
    const r = await assumeRoleWithMfa(opts);
    mfaSession = r.mfaSession;
    return r.credentials;
  };

  return async () => {
    if (!expiresSoon(current)) return current;
    inflight ??= refresh()
      .then((c) => (current = c))
      .finally(() => {
        inflight = undefined;
      });
    return inflight;
  };
}

/** Pure: does a role trust policy let `caller` assume it, and with which conditions? */
export function analyzeTrustPolicy(
  doc: string | Record<string, unknown> | undefined,
  caller: CallerInfo,
): { trusted: boolean; via?: "you" | "your-account" | "anyone"; mfaRequired: boolean; externalIdRequired: boolean } {
  const none = { trusted: false, mfaRequired: false, externalIdRequired: false };
  if (!doc) return none;
  let policy: { Statement?: unknown };
  try {
    policy = typeof doc === "string" ? JSON.parse(decodeURIComponent(doc)) : doc;
  } catch {
    return none;
  }
  const arr = <T>(v: T | T[] | undefined): T[] => (v === undefined ? [] : Array.isArray(v) ? v : [v]);
  const me = new Set([caller.arn, caller.roleArn].filter(Boolean));
  const accountRoot = `arn:aws:iam::${caller.account}:root`;

  for (const st of arr(policy.Statement as Record<string, any>[])) { // eslint-disable-line @typescript-eslint/no-explicit-any
    if (st.Effect !== "Allow") continue;
    if (!arr<string>(st.Action).some((a) => a === "sts:AssumeRole" || a === "sts:*" || a === "*")) continue;
    const principals = st.Principal === "*" ? ["*"] : arr<string>(st.Principal?.AWS);
    let via: "you" | "your-account" | "anyone" | undefined;
    if (principals.some((p) => me.has(p))) via = "you";
    else if (principals.some((p) => p === accountRoot || p === caller.account)) via = "your-account";
    else if (principals.includes("*")) via = "anyone";
    if (!via) continue;

    const cond = JSON.stringify(st.Condition ?? {});
    return {
      trusted: true,
      via,
      mfaRequired: /aws:MultiFactorAuth(Present|Age)/i.test(cond),
      externalIdRequired: /sts:ExternalId/i.test(cond),
    };
  }
  return none;
}
