import { z } from "zod";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { STSClient, GetCallerIdentityCommand } from "@aws-sdk/client-sts";
import { IAMClient, ListRolesCommand, type Role } from "@aws-sdk/client-iam";
import type { AwsClientFactory } from "./aws-client.js";
import { GuardrailViolation } from "./guardrails.js";
import { bestEffort } from "./helpers.js";
import {
  analyzeTrustPolicy,
  assumeRoleWithMfa,
  detectMfaSerial,
  parseCallerArn,
  refreshingRoleProvider,
  type AssumeOptions,
} from "./mfa.js";
import { askMfaCode, canElicit, confirmWithUser } from "./runner.js";

const text = (obj: unknown, isError = false) => ({
  content: [{ type: "text" as const, text: typeof obj === "string" ? obj : JSON.stringify(obj, null, 2) }],
  ...(isError ? { isError: true } : {}),
});

/** RoleSessionName allows [\w+=,.@-], max 64 chars. */
const sessionName = (label: string) => `devops-copilot-${label}`.replace(/[^\w+=,.@-]/g, "-").slice(0, 64);

/**
 * Role tools: discover which roles you can assume, and assume one (with MFA
 * when needed) as a session-scoped account — no passwords, only a 6-digit
 * code typed into the client's own prompt.
 */
export function registerRoleTools(server: McpServer, factory: AwsClientFactory): void {
  server.registerTool(
    "list_assumable_roles",
    {
      description:
        "[READ] Find IAM roles you can assume: (1) roles configured as profiles in ~/.aws/config (role_arn), and " +
        "(2) roles in the current account whose trust policy allows you or your account, with whether MFA or an " +
        "ExternalId is required. Also reports your identity and detected MFA device. Use the roleArn with assume_role.",
      inputSchema: {
        account: z.string().optional().describe("Account whose credentials to check with. Omit for default."),
      },
    },
    async (args: { account?: string }) => {
      try {
        const account = factory.resolveAccount(args.account);
        const region = factory.resolveRegion(account);
        const creds = factory.credentialsFor(account);

        const configuredProfiles = factory
          .listAccounts()
          .map((a) => ({ a, cfg: factory.profileConfig(a.id) }))
          .filter(({ cfg }) => cfg.role_arn)
          .map(({ a, cfg }) => ({
            account: a.id,
            roleArn: cfg.role_arn,
            sourceProfile: cfg.source_profile,
            mfaSerial: cfg.mfa_serial,
            howToUse: `switch_account "${a.id}" (or pass account: "${a.id}" to any tool)${cfg.mfa_serial ? " — MFA code asked only if needed" : ""}`,
          }));

        const mfa = await bestEffort(() =>
          detectMfaSerial(creds, region, { configuredSerial: factory.profileConfig(account.id).mfa_serial }),
        );

        const trusted = await bestEffort(async () => {
          const caller =
            mfa.status === "checked"
              ? mfa.data.caller
              : parseCallerArn(
                  (await new STSClient({ region, credentials: creds }).send(new GetCallerIdentityCommand({}))).Arn!,
                );
          const iam = new IAMClient({ region: "us-east-1", credentials: creds });
          const roles: Role[] = [];
          let Marker: string | undefined;
          do {
            const res = await iam.send(new ListRolesCommand({ Marker, MaxItems: 1000 }));
            roles.push(...(res.Roles ?? []));
            Marker = res.IsTruncated ? res.Marker : undefined;
          } while (Marker && roles.length < 3000);
          const rank = { you: 0, "your-account": 1, anyone: 2 } as const;
          return roles
            .map((r) => ({ r, t: analyzeTrustPolicy(r.AssumeRolePolicyDocument, caller) }))
            .filter(({ t }) => t.trusted)
            .sort((a, b) => rank[a.t.via!] - rank[b.t.via!])
            .map(({ r, t }) => ({
              roleArn: r.Arn,
              name: r.RoleName,
              trustedVia: t.via,
              mfaRequired: t.mfaRequired,
              externalIdRequired: t.externalIdRequired || undefined,
              maxSessionHours: r.MaxSessionDuration ? r.MaxSessionDuration / 3600 : undefined,
              description: r.Description,
            }));
        });

        return text({
          _account: account.id,
          identity: mfa.status === "checked" ? mfa.data.caller : undefined,
          mfaDevice:
            mfa.status === "checked"
              ? { serial: mfa.data.serial, source: mfa.data.source, note: mfa.data.note }
              : { skipped: mfa.reason },
          configuredProfiles,
          trustedRolesInThisAccount:
            trusted.status === "checked" ? trusted.data.slice(0, 100) : { skipped: trusted.reason },
          notes: [
            'trustedVia "you" = the trust policy names you directly; "your-account" = it trusts your whole account, so your own IAM policy must also allow sts:AssumeRole on it.',
            "Roles in OTHER accounts can't be listed from here — assume them by ARN if you know it.",
          ],
        });
      } catch (err) {
        return text(`Error in list_assumable_roles: ${String(err)}`, true);
      }
    },
  );

  server.registerTool(
    "assume_role",
    {
      description:
        "[READ] Ad-hoc: assume a role by ARN for this session only (for roles saved with `awscm role add`, " +
        "use switch_account instead). Registers it as a temporary account (usable via the " +
        "`account` parameter of every tool). Requires interactive user approval. MFA is handled automatically: the " +
        "server finds your MFA device and, only if the role needs it, asks YOU (not the model) for the 6-digit code " +
        "in a client prompt — no passwords. Credentials refresh silently for up to 12h. Access is bounded by the " +
        "role's own permissions.",
      inputSchema: {
        roleArn: z.string().max(2048).describe("ARN of the role, e.g. arn:aws:iam::123456789012:role/ReadOnly (see list_assumable_roles)"),
        label: z
          .string()
          .regex(/^[A-Za-z0-9_.-]{1,64}$/)
          .describe("Short account id to register it under, e.g. 'prod-readonly'. Used as the `account` parameter."),
        sourceAccount: z
          .string()
          .optional()
          .describe("Existing account id whose credentials perform the AssumeRole call. Omit for the default account."),
        mfaSerial: z
          .string()
          .max(256)
          .optional()
          .describe("MFA device ARN. Omit to auto-detect (profile mfa_serial, then your IAM user's registered device)."),
        durationMinutes: z
          .number()
          .int()
          .min(15)
          .max(720)
          .optional()
          .describe("Role session length (default 60; max is set by the role, and 60 when chaining roles)"),
        externalId: z.string().max(1224).optional().describe("ExternalId, if the role's trust policy requires one"),
        region: z.string().optional().describe("Default region for the new account. Omit to inherit."),
      },
    },
    async (args: {
      roleArn: string;
      label: string;
      sourceAccount?: string;
      mfaSerial?: string;
      durationMinutes?: number;
      externalId?: string;
      region?: string;
    }) => {
      try {
        if (!canElicit(server)) {
          throw new GuardrailViolation(
            "assume_role requires interactive user approval, but this MCP client does not support elicitation. " +
              "In a terminal: `awscm role add <name> <role-arn>` then `awscm role use <name>`.",
          );
        }
        const source = factory.resolveAccount(args.sourceAccount);
        const region = args.region ?? factory.resolveRegion(source);
        const sourceCredentials = factory.credentialsFor(source);
        const configuredSerial = args.mfaSerial ?? factory.profileConfig(source.id).mfa_serial;

        const detection = await detectMfaSerial(sourceCredentials, region, { configuredSerial });
        await confirmWithUser(
          server,
          `Assume IAM role ${args.roleArn} as account "${args.label}" using credentials of "${source.id}" ` +
            `(${detection.caller.arn})?` +
            (detection.serial ? `\nMFA device: ${detection.serial} — you'll be asked for a code only if the role requires it.` : ""),
        );

        const opts: AssumeOptions = {
          sourceCredentials,
          roleArn: args.roleArn,
          region,
          serial: detection.serial,
          mfaRequired: Boolean(configuredSerial),
          getCode: (serial, purpose) => askMfaCode(server, serial, purpose),
          sessionName: sessionName(args.label),
          roleDurationSeconds: (args.durationMinutes ?? 60) * 60,
          externalId: args.externalId,
        };
        const result = await assumeRoleWithMfa(opts);
        const credentials = refreshingRoleProvider(opts, result);

        // Prove the role works before registering it.
        const identity = await new STSClient({ region, credentials }).send(new GetCallerIdentityCommand({}));
        factory.registerEphemeralAccount(
          {
            id: args.label,
            profile: "",
            defaultRegion: region,
            description: `Assumed role ${args.roleArn} (session-scoped, via ${source.id}${result.mfaUsed ? " + MFA" : ""})`,
          },
          credentials,
          { replace: true },
        );
        return text({
          registered: args.label,
          identity: { account: identity.Account, arn: identity.Arn },
          mfa: result.mfaUsed
            ? { used: true, device: detection.serial, detectedVia: detection.source, flow: result.flow }
            : { used: false, note: detection.serial ? "role did not require MFA" : detection.note },
          expires: result.credentials.expiration?.toISOString(),
          refresh: result.mfaSession
            ? `auto-refreshes from the MFA session until ${result.mfaSession.expiration?.toISOString()}, then asks for a new code`
            : "re-run assume_role with the same label when it expires",
          note: "Session-scoped: gone when the server restarts. Use it via the `account` parameter.",
        });
      } catch (err) {
        const message = err instanceof GuardrailViolation ? err.message : `Error in assume_role: ${String(err)}`;
        return text(message, true);
      }
    },
  );
}
