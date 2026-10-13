import { describe, it, expect } from "vitest";
import { z } from "zod";
import { parseToolMarkdown, buildRequest, buildInputSchema } from "../src/core/md-tools.js";
import { assertReadAllowed, isReadOperation, redact, shapeOutput, loadSdkCommand } from "../src/core/aws-ops.js";

const VPCS_MD = `---
name: list_vpcs
service: ec2
operation: DescribeVpcs
params:
  vpcIds: { type: "string[]", optional: true, mapsTo: VpcIds, description: "Only these VPCs" }
  isDefault: { type: boolean, optional: true, filter: is-default }
fixed: { MaxResults: 100 }
output: "Vpcs[].{id: VpcId, cidr: CidrBlock}"
---
List VPCs with their CIDR ranges and default flag.
`;

describe("markdown tool parsing", () => {
  it("parses frontmatter + body into a spec", () => {
    const spec = parseToolMarkdown(VPCS_MD);
    expect(spec.name).toBe("list_vpcs");
    expect(spec.risk).toBe("read");
    expect(spec.description).toMatch(/List VPCs/);
    expect(spec.params.vpcIds.mapsTo).toBe("VpcIds");
  });

  it("rejects a write operation labelled read", () => {
    const md = VPCS_MD.replace("DescribeVpcs", "DeleteVpc");
    expect(() => parseToolMarkdown(md, "evil.tool.md")).toThrow(/evil\.tool\.md.*not read-only/);
  });

  it("rejects sensitive read operations", () => {
    const md = VPCS_MD.replace("service: ec2", "service: secrets-manager").replace("DescribeVpcs", "GetSecretValue");
    expect(() => parseToolMarkdown(md)).toThrow(/blocked/);
  });

  it("rejects unknown keys and missing description", () => {
    expect(() => parseToolMarkdown(VPCS_MD.replace("fixed:", "fixd:"))).toThrow(/invalid tool spec/);
    expect(() => parseToolMarkdown(VPCS_MD.split("---\n").slice(0, 2).join("---\n") + "---\n")).toThrow(
      /description/,
    );
  });
});

describe("request building", () => {
  const spec = parseToolMarkdown(VPCS_MD);

  it("maps args, filters, and fixed fields", () => {
    expect(buildRequest(spec, { vpcIds: ["vpc-1"], isDefault: true })).toEqual({
      MaxResults: 100,
      VpcIds: ["vpc-1"],
      Filters: [{ Name: "is-default", Values: ["true"] }],
    });
  });

  it("omits unset params and never mutates fixed", () => {
    expect(buildRequest(spec, {})).toEqual({ MaxResults: 100 });
    buildRequest(spec, { isDefault: false });
    expect(spec.fixed).toEqual({ MaxResults: 100 });
  });

  it("generates a bounded zod schema with a limit param", () => {
    const schema = z.object(buildInputSchema(spec));
    expect(schema.safeParse({ vpcIds: ["vpc-1"], limit: 10 }).success).toBe(true);
    expect(schema.safeParse({ vpcIds: "vpc-1" }).success).toBe(false);
    expect(schema.safeParse({ limit: 10_000 }).success).toBe(false);
  });
});

describe("read-only guardrail", () => {
  it("classifies operation names", () => {
    for (const op of ["DescribeVpcs", "ListBuckets", "GetBucketPolicy", "LookupEvents"]) {
      expect(isReadOperation(op)).toBe(true);
    }
    for (const op of ["DeleteBucket", "PutObject", "TerminateInstances", "Get", "Listen", "Describe"]) {
      expect(isReadOperation(op)).toBe(false);
    }
  });

  it("assertReadAllowed blocks writes, secrets, and junk", () => {
    expect(() => assertReadAllowed("DescribeInstances")).not.toThrow();
    expect(() => assertReadAllowed("RunInstances")).toThrow(/not read-only/);
    expect(() => assertReadAllowed("GetPasswordData")).toThrow(/blocked/);
    expect(() => assertReadAllowed("describe_instances")).toThrow(/Invalid operation/);
  });
});

describe("response shaping", () => {
  it("redacts secrets but keeps ids/arns and pagination tokens out", () => {
    const out = redact({
      $metadata: { httpStatusCode: 200 },
      MasterUserPassword: "hunter2",
      SecretArn: "arn:aws:secretsmanager:...",
      Environment: { Variables: { DB_PASS: "x", MODE: "prod" } },
      containerDefinitions: [{ environment: [{ name: "TOKEN", value: "abc" }] }],
      Credentials: { AccessKeyId: "AKIA...", SecretAccessKey: "s3cr3t", SessionToken: "tok" },
    }) as Record<string, any>;
    expect(out.$metadata).toBeUndefined();
    expect(out.MasterUserPassword).toBe("[redacted]");
    expect(out.SecretArn).toMatch(/^arn:/);
    expect(out.Environment.Variables).toEqual({ DB_PASS: "[redacted]", MODE: "[redacted]" });
    expect(out.containerDefinitions[0].environment[0]).toEqual({ name: "TOKEN", value: "[redacted]" });
    expect(out.Credentials).toEqual({ AccessKeyId: "AKIA...", SecretAccessKey: "[redacted]", SessionToken: "[redacted]" });
  });

  it("projects with JMESPath, caps length, flags more pages", () => {
    const res = {
      Vpcs: Array.from({ length: 5 }, (_, i) => ({ VpcId: `vpc-${i}`, CidrBlock: "10.0.0.0/16", Junk: 1 })),
      NextToken: "abc",
      CreateTime: new Date("2026-01-01T00:00:00Z"),
    };
    const out = shapeOutput(res, { output: "Vpcs[].{id: VpcId, cidr: CidrBlock}", limit: 3 });
    expect(out).toEqual({
      count: 3,
      items: [
        { id: "vpc-0", cidr: "10.0.0.0/16" },
        { id: "vpc-1", cidr: "10.0.0.0/16" },
        { id: "vpc-2", cidr: "10.0.0.0/16" },
      ],
      truncated: true,
      moreAvailable: true,
    });
  });

  it("passes objects through and serializes dates", () => {
    const out = shapeOutput({ Created: new Date("2026-01-01T00:00:00Z") }, {});
    expect(out).toEqual({ Created: "2026-01-01T00:00:00.000Z", moreAvailable: undefined });
  });
});

describe("SDK resolution", () => {
  it("resolves installed client + command", async () => {
    const { Client, Command } = await loadSdkCommand("ec2", "DescribeVpcs");
    expect(Client.name).toBe("EC2Client");
    expect(Command.name).toBe("DescribeVpcsCommand");
  });

  it("explains missing packages and operations", async () => {
    await expect(loadSdkCommand("not-a-service", "ListThings")).rejects.toThrow(/npm install @aws-sdk/);
    await expect(loadSdkCommand("ec2", "DescribeUnicorns")).rejects.toThrow(/no operation/);
  });
});
