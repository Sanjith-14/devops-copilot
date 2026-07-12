import { fromIni } from "@aws-sdk/credential-providers";
import { loadSharedConfigFiles } from "@smithy/shared-ini-file-loader";
import type { AwsCredentialIdentityProvider } from "@aws-sdk/types";
import type { AccountConfig, CopilotConfig } from "./types.js";

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

  constructor(private cfg: CopilotConfig) {}

  /**
   * Scan ~/.aws/config + ~/.aws/credentials and register every profile as an
   * account (honoring the allowlist). Must be called once before serving.
   */
  async discoverAccounts(): Promise<void> {
    const { configFile, credentialsFile } = await loadSharedConfigFiles();
    const names = new Set([...Object.keys(configFile ?? {}), ...Object.keys(credentialsFile ?? {})]);

    for (const name of names) {
      if (this.cfg.profileAllowlist && !this.cfg.profileAllowlist.includes(name)) continue;
      const section = { ...(credentialsFile?.[name] ?? {}), ...(configFile?.[name] ?? {}) };
      this.accounts.set(name, {
        id: name,
        profile: name,
        defaultRegion: section.region,
        description: section.role_arn
          ? `AssumeRole via profile (${section.role_arn})`
          : section.sso_account_id || section.sso_session
            ? `SSO${section.sso_account_id ? ` account ${section.sso_account_id}` : ""}${section.sso_role_name ? ` / ${section.sso_role_name}` : ""}`
            : "local credentials",
      });
    }

    if (this.accounts.size === 0) {
      throw new Error(
        "No AWS profiles found in ~/.aws (or none matched DEVOPS_COPILOT_PROFILES). " +
          "Log in first, e.g. `aws configure`, `aws configure sso` + `aws sso login`.",
      );
    }

    // Default account: env preference -> "default" profile -> first discovered.
    const preferred = this.cfg.defaultAccount;
    if (preferred && this.accounts.has(preferred)) this.defaultAccountId = preferred;
    else if (this.accounts.has("default")) this.defaultAccountId = "default";
    else this.defaultAccountId = [...this.accounts.keys()][0];

    if (preferred && !this.accounts.has(preferred)) {
      console.error(
        `[aws] preferred default profile "${preferred}" not found; using "${this.defaultAccountId}". ` +
          `Known: ${[...this.accounts.keys()].join(", ")}`,
      );
    }
  }

  /** Register a runtime (session-scoped) account backed by an explicit credential provider. */
  registerEphemeralAccount(account: AccountConfig, credentials: AwsCredentialIdentityProvider): void {
    if (this.accounts.has(account.id)) {
      throw new Error(`Account id "${account.id}" already exists — pick a different label.`);
    }
    this.accounts.set(account.id, account);
    this.ephemeralCreds.set(account.id, credentials);
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
      creds = fromIni({ profile: account.profile });
      this.credCache.set(account.id, creds);
    }
    return creds;
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
