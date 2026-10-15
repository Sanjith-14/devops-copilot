import {
  IAMClient,
  ListUsersCommand,
  ListMFADevicesCommand,
  ListAccessKeysCommand,
  GetLoginProfileCommand,
  GetAccountSummaryCommand,
  type User,
} from "@aws-sdk/client-iam";
import { S3Client, ListBucketsCommand, GetPublicAccessBlockCommand, GetBucketPolicyStatusCommand } from "@aws-sdk/client-s3";
import { EC2Client, DescribeSecurityGroupsCommand, type SecurityGroup } from "@aws-sdk/client-ec2";
import { RDSClient, DescribeDBInstancesCommand, type DBInstance } from "@aws-sdk/client-rds";
import { SecretsManagerClient, ListSecretsCommand, type SecretListEntry } from "@aws-sdk/client-secrets-manager";
import { z } from "zod";
import type { ToolDefinition, ToolContext } from "../../core/types.js";
import type { AwsClientFactory } from "../../core/aws-client.js";
import { bestEffort, bySeverity, isAccessDenied, mapLimited, type Finding } from "../../core/helpers.js";
import { findWorldOpenRules } from "../ec2/network.js";
import {
  accountSummaryFindings,
  iamUserFindings,
  rdsFindings,
  score,
  secretFindings,
  type IamUserFacts,
} from "./checks.js";

/** Collect "unknown" instead of failing when a per-item call is denied. */
async function orUnknown<T>(fn: () => Promise<T>): Promise<T | "unknown"> {
  try {
    return await fn();
  } catch (err) {
    if (isAccessDenied(err)) return "unknown";
    throw err;
  }
}

export function buildSecurityTools(factory: AwsClientFactory): ToolDefinition[] {
  const client = <T>(Ctor: new (c: never) => T, ctx: ToolContext, region = ctx.region) =>
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    factory.getClient(Ctor as any, ctx.accountId, region).client as T;

  const sections = {
    async iam(ctx: ToolContext, maxUsers: number) {
      const iam = client(IAMClient, ctx, "us-east-1");
      const users: User[] = [];
      let Marker: string | undefined;
      do {
        const res = await iam.send(new ListUsersCommand({ Marker }));
        users.push(...(res.Users ?? []));
        Marker = res.IsTruncated ? res.Marker : undefined;
      } while (Marker && users.length < maxUsers);

      const facts: IamUserFacts[] = await mapLimited(users.slice(0, maxUsers), 5, async (u) => ({
        userName: u.UserName!,
        passwordLastUsed: u.PasswordLastUsed,
        hasConsolePassword: await orUnknown(async () => {
          try {
            await iam.send(new GetLoginProfileCommand({ UserName: u.UserName }));
            return true;
          } catch (err) {
            if (/NoSuchEntity/.test(String(err))) return false;
            throw err;
          }
        }),
        mfaDevices: await orUnknown(async () => (await iam.send(new ListMFADevicesCommand({ UserName: u.UserName }))).MFADevices?.length ?? 0),
        accessKeys: await orUnknown(async () =>
          ((await iam.send(new ListAccessKeysCommand({ UserName: u.UserName }))).AccessKeyMetadata ?? []).map((k) => ({
            id: k.AccessKeyId!,
            status: k.Status,
            created: k.CreateDate,
          })),
        ),
      }));
      const summary = await orUnknown(async () => (await iam.send(new GetAccountSummaryCommand({}))).SummaryMap);
      const unknownChecks = facts.filter((f) => f.mfaDevices === "unknown" || f.accessKeys === "unknown").length;
      return {
        scanned: `${facts.length} of ${users.length}${Marker ? "+" : ""} users`,
        total: facts.length,
        note: unknownChecks ? `MFA/access-key checks denied for ${unknownChecks} user(s) — results incomplete` : undefined,
        findings: [...accountSummaryFindings(summary === "unknown" ? undefined : (summary as Record<string, number>)), ...iamUserFindings(facts)],
      };
    },

    async s3(ctx: ToolContext, maxBuckets: number) {
      const list = await client(S3Client, ctx).send(new ListBucketsCommand({}));
      const buckets = list.Buckets ?? [];
      const findings = (
        await mapLimited(buckets.slice(0, maxBuckets), 10, async (b): Promise<Finding[]> => {
          // Query each bucket in its own region (ListBuckets reports it) to avoid redirects.
          const s3 = client(S3Client, ctx, b.BucketRegion ?? ctx.region);
          const resource = `s3:${b.Name}`;
          const out: Finding[] = [];
          try {
            const pab = (await s3.send(new GetPublicAccessBlockCommand({ Bucket: b.Name }))).PublicAccessBlockConfiguration;
            if (!(pab?.BlockPublicAcls && pab.IgnorePublicAcls && pab.BlockPublicPolicy && pab.RestrictPublicBuckets)) {
              out.push({ severity: "low", resource, issue: "public access block only partially enabled" });
            }
          } catch (err) {
            if (/NoSuchPublicAccessBlockConfiguration/.test(String(err))) {
              out.push({ severity: "medium", resource, issue: "no public access block configured" });
            }
          }
          try {
            const status = await s3.send(new GetBucketPolicyStatusCommand({ Bucket: b.Name }));
            if (status.PolicyStatus?.IsPublic) out.push({ severity: "high", resource, issue: "bucket policy makes it PUBLIC" });
          } catch {
            /* no policy = not public via policy */
          }
          return out;
        })
      ).flat();
      return { scanned: `${Math.min(buckets.length, maxBuckets)} of ${buckets.length} buckets`, total: Math.min(buckets.length, maxBuckets), findings };
    },

    async network(ctx: ToolContext) {
      const groups: SecurityGroup[] = [];
      let NextToken: string | undefined;
      do {
        const res = await client(EC2Client, ctx).send(new DescribeSecurityGroupsCommand({ MaxResults: 1000, NextToken }));
        groups.push(...(res.SecurityGroups ?? []));
        NextToken = res.NextToken;
      } while (NextToken);
      const findings = groups.flatMap((g) =>
        findWorldOpenRules(g.IpPermissions)
          .filter((f) => f.severity !== "info")
          .map((f): Finding => ({ severity: f.severity, resource: `sg:${g.GroupId} (${g.GroupName})`, issue: `${f.rule} — ${f.reason}` })),
      );
      return { scanned: `${groups.length} security groups`, total: groups.length, findings };
    },

    async rds(ctx: ToolContext) {
      const instances: DBInstance[] = [];
      let Marker: string | undefined;
      do {
        const res = await client(RDSClient, ctx).send(new DescribeDBInstancesCommand({ Marker }));
        instances.push(...(res.DBInstances ?? []));
        Marker = res.Marker;
      } while (Marker);
      return { scanned: `${instances.length} DB instances`, total: instances.length, findings: rdsFindings(instances) };
    },

    async secrets(ctx: ToolContext) {
      const secrets: SecretListEntry[] = [];
      let NextToken: string | undefined;
      do {
        const res = await client(SecretsManagerClient, ctx).send(new ListSecretsCommand({ MaxResults: 100, NextToken }));
        secrets.push(...(res.SecretList ?? []));
        NextToken = res.NextToken;
      } while (NextToken && secrets.length < 1000);
      return { scanned: `${secrets.length} secrets`, total: secrets.length, findings: secretFindings(secrets) };
    },
  };

  return [
    {
      name: "scorecard",
      description:
        "One-call security posture report for an account: IAM (root MFA/keys, console users without MFA, old " +
        "access keys), S3 (public buckets, missing public access block), network (security groups open to the " +
        "internet on sensitive ports), RDS (public, unencrypted, no backups) and Secrets Manager (rotation). " +
        "Returns a 0-100 score, letter grade and findings ranked by severity. Sections the caller lacks " +
        "permission for are reported as skipped. Read-only — it never changes anything.",
      risk: "read",
      inputSchema: {
        maxBuckets: z.number().int().min(1).max(1000).optional().describe("S3 buckets to inspect (default 50)"),
        maxUsers: z.number().int().min(1).max(1000).optional().describe("IAM users to inspect (default 100)"),
      },
      handler: async (args, ctx) => {
        const [iam, s3, network, rds, secrets] = await Promise.all([
          bestEffort(() => sections.iam(ctx, (args.maxUsers as number | undefined) ?? 100)),
          bestEffort(() => sections.s3(ctx, (args.maxBuckets as number | undefined) ?? 50)),
          bestEffort(() => sections.network(ctx)),
          bestEffort(() => sections.rds(ctx)),
          bestEffort(() => sections.secrets(ctx)),
        ]);
        const all = { iam, s3, network, rds, secrets };
        const checked = Object.values(all).flatMap((s) => (s.status === "checked" ? [s.data] : []));
        const findings = checked.flatMap((s) => s.findings).sort(bySeverity);
        const count = (sev: string) => findings.filter((f) => f.severity === sev).length;

        return {
          ...score(checked),
          counts: { high: count("high"), medium: count("medium"), low: count("low") },
          sections: Object.fromEntries(
            Object.entries(all).map(([name, s]) => [
              name,
              s.status === "checked"
                ? { status: "checked", scanned: s.data.scanned, findings: s.data.findings.length, note: (s.data as { note?: string }).note }
                : s,
            ]),
          ),
          topFindings: findings.slice(0, 25),
          truncated: findings.length > 25 || undefined,
          note: "Score covers only the sections that were checked. NACLs, IAM policy contents and CloudTrail config are not evaluated.",
        };
      },
    },
  ];
}
