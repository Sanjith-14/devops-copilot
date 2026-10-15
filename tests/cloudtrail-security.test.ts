import { describe, it, expect } from "vitest";
import createCloudTrailModule from "../src/services/cloudtrail/index.js";
import createSecurityModule from "../src/services/security/index.js";
import { chooseLookupAttribute, summarizeEvent, topCounts } from "../src/services/cloudtrail/events.js";
import { accountSummaryFindings, iamUserFindings, rdsFindings, score, secretFindings } from "../src/services/security/checks.js";
import { fakeFactory, ctx } from "./fake-aws.js";

const NOW = Date.parse("2026-10-15T00:00:00Z");
const daysAgo = (d: number) => new Date(NOW - d * 86_400_000);

const event = (name: string, user: string, extra: Record<string, unknown> = {}, readOnly = false) => ({
  EventName: name,
  EventSource: "ec2.amazonaws.com",
  Username: user,
  EventTime: new Date("2026-10-14T10:00:00Z"),
  Resources: [{ ResourceName: "sg-1" }],
  CloudTrailEvent: JSON.stringify({ readOnly, sourceIPAddress: "1.2.3.4", userIdentity: { type: "IAMUser" }, ...extra }),
});

describe("cloudtrail helpers", () => {
  it("summarizes events and redacts request params", () => {
    const s = summarizeEvent(
      event("ModifyDBInstance", "alice", { errorCode: "AccessDenied", requestParameters: { masterUserPassword: "hunter2", dBInstanceIdentifier: "db1" } }),
    );
    expect(s).toMatchObject({ event: "ModifyDBInstance", service: "ec2", user: "alice", sourceIp: "1.2.3.4", readOnly: false, error: "AccessDenied" });
    expect(s.request).toContain("[redacted]");
    expect(s.request).not.toContain("hunter2");
  });

  it("picks the single most selective lookup attribute", () => {
    expect(chooseLookupAttribute({})).toEqual({ AttributeKey: "ReadOnly", AttributeValue: "false" });
    expect(chooseLookupAttribute({ user: "bob", eventSource: "s3" })).toEqual({ AttributeKey: "Username", AttributeValue: "bob" });
    expect(chooseLookupAttribute({ eventSource: "s3" })).toEqual({ AttributeKey: "EventSource", AttributeValue: "s3.amazonaws.com" });
    expect(chooseLookupAttribute({ resourceName: "sg-1", user: "x" }).AttributeKey).toBe("ResourceName");
  });

  it("counts top values", () => {
    expect(topCounts(["a", "b", "a", undefined])).toEqual([{ name: "a", count: 2 }, { name: "b", count: 1 }]);
  });
});

describe("cloudtrail tools", () => {
  it("recent_changes drops reads and AWS-service noise, filters by service client-side", async () => {
    const { factory, calls } = fakeFactory({
      LookupEventsCommand: {
        Events: [
          event("AuthorizeSecurityGroupIngress", "alice"),
          event("DescribeInstances", "alice", {}, true),
          event("UpdateAutoScalingGroup", "autoscaling", { userIdentity: { type: "AWSService" }, sourceIPAddress: "autoscaling.amazonaws.com" }),
          { ...event("PutBucketPolicy", "bob"), EventSource: "s3.amazonaws.com" },
        ],
      },
    });
    const [recent] = createCloudTrailModule(factory).tools;
    const all = (await recent.handler({}, ctx)) as any;
    expect(all.events.map((e: any) => e.event)).toEqual(["AuthorizeSecurityGroupIngress", "PutBucketPolicy"]);
    expect(calls[0].input.LookupAttributes).toEqual([{ AttributeKey: "ReadOnly", AttributeValue: "false" }]);

    const ec2Only = (await recent.handler({ eventSource: "ec2" }, ctx)) as any;
    expect(ec2Only.events.map((e: any) => e.event)).toEqual(["AuthorizeSecurityGroupIngress"]);
    expect(ec2Only.topUsers).toEqual([{ name: "alice", count: 1 }]);
  });

  it("resource_history looks up by resource name", async () => {
    const { factory, calls } = fakeFactory({ LookupEventsCommand: { Events: [event("RevokeSecurityGroupIngress", "carol")] } });
    const out = (await createCloudTrailModule(factory).tools[1].handler({ resourceName: "sg-1" }, ctx)) as any;
    expect(calls[0].input.LookupAttributes[0]).toEqual({ AttributeKey: "ResourceName", AttributeValue: "sg-1" });
    expect(out.lastChange).toMatchObject({ event: "RevokeSecurityGroupIngress", user: "carol" });
  });
});

describe("security checks", () => {
  it("RDS: public, unencrypted, no backups, no deletion protection", () => {
    const f = rdsFindings([
      { DBInstanceIdentifier: "db1", PubliclyAccessible: true, StorageEncrypted: false, BackupRetentionPeriod: 0, DeletionProtection: false },
      { DBInstanceIdentifier: "db2", PubliclyAccessible: false, StorageEncrypted: true, BackupRetentionPeriod: 7, DeletionProtection: true },
    ]);
    expect(f.map((x) => x.severity)).toEqual(["high", "medium", "medium", "low"]);
    expect(f.every((x) => x.resource === "rds:db1")).toBe(true);
  });

  it("IAM: console without MFA, stale keys; unknown is not a finding", () => {
    const f = iamUserFindings(
      [
        { userName: "a", hasConsolePassword: true, mfaDevices: 0, accessKeys: [{ id: "AKIAOLDKEY000", status: "Active", created: daysAgo(200) }] },
        { userName: "b", hasConsolePassword: true, mfaDevices: 1, accessKeys: [{ id: "AKIANEW", status: "Active", created: daysAgo(10) }] },
        { userName: "c", hasConsolePassword: "unknown", mfaDevices: "unknown", accessKeys: "unknown" },
      ],
      NOW,
    );
    expect(f).toEqual([
      { severity: "high", resource: "iam-user:a", issue: "console access without MFA" },
      expect.objectContaining({ severity: "medium", resource: "iam-user:a", issue: expect.stringMatching(/200 days old/) }),
    ]);
    expect(accountSummaryFindings({ AccountMFAEnabled: 0, AccountAccessKeysPresent: 1 })).toHaveLength(2);
  });

  it("secrets: rotation disabled / stale", () => {
    const f = secretFindings(
      [
        { Name: "s1", RotationEnabled: false, LastChangedDate: daysAgo(400) },
        { Name: "s2", RotationEnabled: true, LastRotatedDate: daysAgo(365) },
        { Name: "s3", RotationEnabled: true, LastRotatedDate: daysAgo(30) },
      ],
      NOW,
    );
    expect(f.map((x) => [x.resource, x.severity])).toEqual([["secret:s1", "low"], ["secret:s2", "low"]]);
  });

  it("scores by pass rate; a high finding caps the grade at C", () => {
    const f = (severity: "high" | "medium" | "low", resource: string) => ({ severity, resource, issue: "x" });
    expect(score([])).toMatchObject({ score: 100, grade: "A" });
    // 189 low findings don't move the score.
    expect(score([{ total: 190, findings: Array.from({ length: 189 }, (_, i) => f("low", `s${i}`)) }])).toMatchObject({ score: 100, grade: "A" });
    // 1 of 10 buckets failing (two findings on the same bucket count once) + 0 of 10 DBs -> 95, but HIGH caps at C.
    expect(score([{ total: 10, findings: [f("high", "b1"), f("medium", "b1")] }, { total: 10, findings: [] }])).toMatchObject({ score: 95, grade: "C" });
    expect(score([{ total: 4, findings: [f("medium", "a"), f("medium", "b"), f("medium", "c")] }])).toMatchObject({ score: 25, grade: "F" });
  });
});

describe("security_scorecard", () => {
  it("combines sections and reports denied ones as skipped", async () => {
    const accessDenied = new Error("AccessDenied: User is not authorized to perform: iam:ListUsers");
    const { factory } = fakeFactory({
      ListUsersCommand: accessDenied,
      ListBucketsCommand: { Buckets: [{ Name: "open-bucket" }] },
      GetPublicAccessBlockCommand: Object.assign(new Error("NoSuchPublicAccessBlockConfiguration"), {}),
      GetBucketPolicyStatusCommand: { PolicyStatus: { IsPublic: true } },
      DescribeSecurityGroupsCommand: {
        SecurityGroups: [{ GroupId: "sg-1", GroupName: "ssh", IpPermissions: [{ IpProtocol: "tcp", FromPort: 22, ToPort: 22, IpRanges: [{ CidrIp: "0.0.0.0/0" }] }] }],
      },
      DescribeDBInstancesCommand: { DBInstances: [{ DBInstanceIdentifier: "db1", PubliclyAccessible: true, StorageEncrypted: true, BackupRetentionPeriod: 7, DeletionProtection: true }] },
      ListSecretsCommand: { SecretList: [] },
    });
    const out = (await createSecurityModule(factory).tools[0].handler({}, ctx)) as any;
    expect(out.sections.iam).toMatchObject({ status: "skipped", reason: expect.stringMatching(/no permission/) });
    expect(out.sections.s3).toMatchObject({ status: "checked", findings: 2 });
    expect(out.counts.high).toBe(3); // public bucket policy, SSH open, public RDS
    expect(out.topFindings[0].severity).toBe("high");
    // s3: 1/1 bucket failing (0%), network: 1/1 SG (0%), rds: 1/1 (0%), secrets: no resources -> excluded.
    expect(out).toMatchObject({ score: 0, grade: "F" });
  });
});
