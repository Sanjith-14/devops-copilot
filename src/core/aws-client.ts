import { fromIni } from "@aws-sdk/credential-providers";
import type { AwsCredentialIdentity, AwsCredentialIdentityProvider } from "@aws-sdk/types";
import type { AccountConfig, CopilotConfig } from "./types.js";
import { awsFilesStamp, loadAwsFiles, profileSection } from "./aws-files.js";
import { ACTIVE_PROFILE, getRoleCredentials, isRoleProfile } from "./roles.js";
import { SESSION_PROFILE } from "./login.js";

/** Human description of a profile for list_accounts. Pure. */
export function describeProfile(name: string, s: Record<string, string | undefined>, now = Date.now()): string {
  const until = (iso?: string) => {
    if (!iso) return "";
    const t = new Date(iso);
    return t.getTime() > now ? ` until ${t.toISOString()}` : " (EXPIRED)";
  };
  if (name === ACTIVE_PROFILE) {
    return `Active role "${s.copilot_role ?? "?"}" (${s.copilot_role_arn ?? "?"})${until(s.copilot_expiration)} — switch with \`awscm role use <name>\``;
  }
  if (name === SESSION_PROFILE) return `MFA session for "${s.copilot_source_profile ?? "?"}"${until(s.copilot_expiration)}`;
  if (isRoleProfile(s)) return `Role ${s.role_arn} via "${s.source_profile}"${s.mfa_serial ? " (MFA if needed)" : ""}`;
  if (s.sso_account_id || s.sso_session) {
    return `SSO${s.sso_account_id ? ` account ${s.sso_account_id}` : ""}${s.sso_role_name ? ` / ${s.sso_role_name}` : ""}`;
  }
  return "local credentials";
}

/** Asks the human for an MFA code (wired to MCP elicitation by the server). */
export type MfaCodeProvider = (serial: string, purpose: string) => Promise<string>;

/**
 * Cache a credential provider's result until 5 minutes before expiry, with
 * one in-flight refresh at a time — so an MFA-protected profile prompts once,
 * not once per concurrent API call.
 */
export function memoizeCredentials(provider: AwsCredentialIdentityProvider): AwsCredentialIdentityProvider {
  let current: AwsCredentialIdentity | undefined;
  let inflight: Promise<AwsCredentialIdentity> | undefined;
  return async () => {
    if (current && (!current.expiration || current.expiration.getTime() - Date.now() > 5 * 60_000)) return current;
    inflight ??= provider()
      .then((c) => (current = c))
      .finally(() => {
        inflight = undefined;
      });
    return inflight;
  };
}

/**
 * Central factory for AWS SDK v3 clients.
 *
 * Design goals:
 *  - Zero config files: accounts are DISCOVERED from ~/.aws profiles at
 *    startup (optionally narrowed by DEVOPS_COPILOT_PROFILES). Whatever the
 *    user logged in with — static keys, SSO (`aws sso login`), or
 *    role_arn/source_profile entries — becomes a selectable account, and IAM
 *    remains the real permission boundary.
 *  - Service modules NEVER touch credentials or profiles. They ask for a
 *    client by (ClientClass, accountId, region) and get a ready one back.
 *  - The assume_role core tool can register EPHEMERAL accounts at runtime
 *    (session-scoped, backed by STS temp credentials, user-confirmed).
 *  - Clients are cached per (service, account, region) so we don't re-assume
 *    roles or re-resolve SSO tokens on every tool call.
 */
export class AwsClientFactory {
  private credCache = new Map<string, AwsCredentialIdentityProvider>();
  private clientCache = new Map<string, unknown>();
  private accounts = new Map<string, AccountConfig>();
  /** Runtime credential providers for ephemeral (assumed-role) accounts. */
  private ephemeralCreds = new Map<string, AwsCredentialIdentityProvider>();
  private defaultAccountId = "default";
  /** Raw ~/.aws config sections per profile (role_arn, mfa_serial, source_profile, ...). */
  private sections = new Map<string, Record<string, string | undefined>>();
  /** mtime stamp of the ~/.aws files at last discovery ("" = never discovered). */
  private stamp = "";
  /** Default picked via switch_account; survives reloads. */
  private chosenDefault?: string;
  private mfaCodeProvider: MfaCodeProvider = async (serial) => {
    throw new Error(
      `MFA code required for ${serial}, but this client cannot prompt. ` +
        "Run `awscm role use <name>` (or `awscm login`) in a terminal first.",
    );
  };

  constructor(private cfg: CopilotConfig) {}

  /** The server installs an interactive (elicitation-based) MFA prompt here. */
  setMfaCodeProvider(provider: MfaCodeProvider): void {
    this.mfaCodeProvider = provider;
  }

  getMfaCodeProvider(): MfaCodeProvider {
    return this.mfaCodeProvider;
  }

  /** ~/.aws settings for a discovered profile (empty for ephemeral accounts). */
  profileConfig(accountId: string): Record<string, string | undefined> {
    return this.sections.get(accountId) ?? {};
  }

  /**
   * Scan ~/.aws/config + ~/.aws/credentials and register every profile as an
   * account (honoring the allowlist). Called at startup and again by
   * refreshIfChanged() whenever the files change; assumed-role (ephemeral)
   * accounts survive reloads.
   */
  async discoverAccounts(): Promise<void> {
    const files = await loadAwsFiles();
    this.stamp = awsFilesStamp();
    for (const id of [...this.accounts.keys()]) if (!this.ephemeralCreds.has(id)) this.accounts.delete(id);
    this.sections.clear();

    const names = new Set([...Object.keys(files.config), ...Object.keys(files.credentials)]);
    for (const name of names) {
      if (this.cfg.profileAllowlist && !this.cfg.profileAllowlist.includes(name)) continue;
      const section = profileSection(files, name);
      this.sections.set(name, section);
      this.accounts.set(name, { id: name, profile: name, defaultRegion: section.region, description: describeProfile(name, section) });
    }

    if (this.accounts.size === 0) {
      throw new Error(
        "No AWS profiles found in ~/.aws (or none matched DEVOPS_COPILOT_PROFILES). " +
          "Log in first, e.g. `aws configure`, `aws configure sso` + `aws sso login`.",
      );
    }

    // Default account: chosen in-session -> env preference -> "default" -> first discovered.
    const preferred = this.cfg.defaultAccount;
    if (this.chosenDefault && this.accounts.has(this.chosenDefault)) this.defaultAccountId = this.chosenDefault;
    else if (preferred && this.accounts.has(preferred)) this.defaultAccountId = preferred;
    else if (this.accounts.has("default")) this.defaultAccountId = "default";
    else this.defaultAccountId = [...this.accounts.keys()][0];

    if (preferred && !this.accounts.has(preferred)) {
      console.error(
        `[aws] preferred default profile "${preferred}" not found; using "${this.defaultAccountId}". ` +
          `Known: ${[...this.accounts.keys()].join(", ")}`,
      );
    }
  }

  /**
   * Hot-reload: if ~/.aws changed (e.g. `awscm role use x` in a
   * terminal), re-discover profiles and drop cached credentials/clients so
   * the next call uses the new role — no MCP client restart needed.
   */
  async refreshIfChanged(): Promise<boolean> {
    if (!this.stamp || awsFilesStamp() === this.stamp) return false;
    try {
      await this.discoverAccounts();
    } catch (err) {
      this.stamp = awsFilesStamp();
      console.error(`[aws] reload of ~/.aws failed, keeping previous accounts: ${String(err)}`);
      return false;
    }
    this.credCache.clear();
    for (const key of [...this.clientCache.keys()]) {
      if (!this.ephemeralCreds.has(key.split(":")[1])) this.clientCache.delete(key);
    }
    console.error("[aws] ~/.aws changed — profiles reloaded");
    return true;
  }

  /** Switch the default account for the rest of this session (switch_account tool). */
  setDefaultAccount(accountId: string): void {
    this.resolveAccount(accountId);
    this.chosenDefault = accountId;
    this.defaultAccountId = accountId;
  }

  /**
   * Register a runtime (session-scoped) account backed by an explicit
   * credential provider. `replace` re-registers an existing *ephemeral*
   * account (e.g. re-assuming a role); discovered profiles are never replaced.
   */
  registerEphemeralAccount(
    account: AccountConfig,
    credentials: AwsCredentialIdentityProvider,
    opts: { replace?: boolean } = {},
  ): void {
    if (this.accounts.has(account.id)) {
      if (!(opts.replace && this.ephemeralCreds.has(account.id))) {
        throw new Error(`Account id "${account.id}" already exists — pick a different label.`);
      }
      // Drop clients bound to the old credentials.
      for (const key of [...this.clientCache.keys()]) if (key.includes(`:${account.id}:`)) this.clientCache.delete(key);
    }
    this.accounts.set(account.id, account);
    this.ephemeralCreds.set(account.id, memoizeCredentials(credentials));
  }

  listAccounts(): AccountConfig[] {
    return [...this.accounts.values()];
  }

  defaultAccount(): string {
    return this.defaultAccountId;
  }

  resolveAccount(accountId?: string): AccountConfig {
    const id = accountId ?? this.defaultAccountId;
    const acct = this.accounts.get(id);
    if (!acct) {
      const known = [...this.accounts.keys()].join(", ");
      throw new Error(`Unknown account "${id}". Known accounts: ${known}`);
    }
    return acct;
  }

  resolveRegion(account: AccountConfig, region?: string): string {
    return region ?? account.defaultRegion ?? this.cfg.defaultRegion;
  }

  credentialsFor(account: AccountConfig): AwsCredentialIdentityProvider {
    const ephemeral = this.ephemeralCreds.get(account.id);
    if (ephemeral) return ephemeral;

    let creds = this.credCache.get(account.id);
    if (!creds) {
      const section = this.profileConfig(account.id);
      creds = isRoleProfile(section) && !section.credential_source
        ? // Role profiles use the same flow as `awscm role use`: reuse
          // today's MFA session if cached, else ask for a code (MCP elicitation)
          // only if the role needs it.
          memoizeCredentials(async () =>
            (await getRoleCredentials(account.profile, {
              getCode: (serial) => this.mfaCodeProvider(serial, `assume role "${account.profile}"`),
            })).credentials,
          )
        : memoizeCredentials(
            fromIni({
              profile: account.profile,
              ignoreCache: true,
              mfaCodeProvider: (serial: string) => this.mfaCodeProvider(serial, `profile "${account.profile}"`),
            }),
          );
      this.credCache.set(account.id, creds);
    }
    return creds;
  }

  /**
   * Resolve credentials up front (may prompt for MFA). The registry calls
   * this before starting a tool's timeout so a human typing a code isn't
   * counted against it.
   */
  async ensureCredentials(account: AccountConfig): Promise<void> {
    await this.credentialsFor(account)();
  }

  /**
   * Get (or create) a cached SDK client.
   * Usage: factory.getClient(S3Client, "prod", "ap-south-1")
   */
  getClient<T>(
    ClientCtor: new (config: { region: string; credentials: AwsCredentialIdentityProvider }) => T,
    accountId?: string,
    region?: string,
  ): { client: T; accountId: string; region: string } {
    const account = this.resolveAccount(accountId);
    const resolvedRegion = this.resolveRegion(account, region);
    const key = `${ClientCtor.name}:${account.id}:${resolvedRegion}`;

    let client = this.clientCache.get(key) as T | undefined;
    if (!client) {
      client = new ClientCtor({
        region: resolvedRegion,
        credentials: this.credentialsFor(account),
      });
      this.clientCache.set(key, client);
    }
    return { client, accountId: account.id, region: resolvedRegion };
  }
}
