import {
  S3Client,
  ListBucketsCommand,
  GetPublicAccessBlockCommand,
  GetBucketPolicyStatusCommand,
  GetBucketEncryptionCommand,
  ListObjectsV2Command,
  GetBucketLocationCommand,
} from "@aws-sdk/client-s3";
import { z } from "zod";
import type { ToolDefinition, ToolContext } from "../../core/types.js";
import type { AwsClientFactory } from "../../core/aws-client.js";

/**
 * S3 tools. Note the pattern: each handler receives ctx (already-resolved
 * account + region) and asks the factory for a client. Zero credential code.
 */
export function buildS3Tools(factory: AwsClientFactory): ToolDefinition[] {
  const s3 = (ctx: ToolContext) => factory.getClient(S3Client, ctx.accountId, ctx.region).client;

  return [
    {
      name: "list_buckets",
      description: "List all S3 buckets in the account with creation dates.",
      risk: "read",
      inputSchema: {},
      handler: async (_args, ctx) => {
        const res = await s3(ctx).send(new ListBucketsCommand({}));
        return {
          count: res.Buckets?.length ?? 0,
          buckets: (res.Buckets ?? []).map((b) => ({ name: b.Name, created: b.CreationDate })),
        };
      },
    },
    {
      name: "check_bucket_public_access",
      description:
        "Security check: report whether a bucket's Public Access Block is fully enabled and whether its policy makes it public.",
      risk: "read",
      inputSchema: { bucket: z.string().describe("Bucket name to inspect") },
      handler: async (args, ctx) => {
        const bucket = args.bucket as string;
        const client = s3(ctx);

        let publicAccessBlock: Record<string, boolean | undefined> | string;
        try {
          const pab = await client.send(new GetPublicAccessBlockCommand({ Bucket: bucket }));
          publicAccessBlock = {
            blockPublicAcls: pab.PublicAccessBlockConfiguration?.BlockPublicAcls,
            ignorePublicAcls: pab.PublicAccessBlockConfiguration?.IgnorePublicAcls,
            blockPublicPolicy: pab.PublicAccessBlockConfiguration?.BlockPublicPolicy,
            restrictPublicBuckets: pab.PublicAccessBlockConfiguration?.RestrictPublicBuckets,
          };
        } catch {
          publicAccessBlock = "NOT CONFIGURED (finding: no public access block set)";
        }

        let policyIsPublic: boolean | string;
        try {
          const status = await client.send(new GetBucketPolicyStatusCommand({ Bucket: bucket }));
          policyIsPublic = status.PolicyStatus?.IsPublic ?? false;
        } catch {
          policyIsPublic = "no bucket policy";
        }

        return { bucket, publicAccessBlock, policyIsPublic };
      },
    },
    {
      name: "check_bucket_encryption",
      description: "Report the default server-side encryption configuration of a bucket.",
      risk: "read",
      inputSchema: { bucket: z.string().describe("Bucket name to inspect") },
      handler: async (args, ctx) => {
        const bucket = args.bucket as string;
        try {
          const res = await s3(ctx).send(new GetBucketEncryptionCommand({ Bucket: bucket }));
          const rules = res.ServerSideEncryptionConfiguration?.Rules ?? [];
          return {
            bucket,
            encrypted: rules.length > 0,
            rules: rules.map((r) => ({
              algorithm: r.ApplyServerSideEncryptionByDefault?.SSEAlgorithm,
              kmsKey: r.ApplyServerSideEncryptionByDefault?.KMSMasterKeyID,
              bucketKeyEnabled: r.BucketKeyEnabled,
            })),
          };
        } catch (err) {
          return { bucket, encrypted: false, detail: `No encryption config readable: ${String(err)}` };
        }
      },
    },
    {
      name: "list_objects",
      description: "List up to `limit` objects in a bucket, optionally under a prefix. Returns keys, sizes, and last-modified.",
      risk: "read",
      inputSchema: {
        bucket: z.string().describe("Bucket name"),
        prefix: z.string().optional().describe("Key prefix filter, e.g. 'logs/2026/'"),
        limit: z.number().int().min(1).max(1000).optional().describe("Max objects to return (default 50)"),
      },
      handler: async (args, ctx) => {
        const res = await s3(ctx).send(
          new ListObjectsV2Command({
            Bucket: args.bucket as string,
            Prefix: args.prefix as string | undefined,
            MaxKeys: (args.limit as number | undefined) ?? 50,
          }),
        );
        return {
          bucket: args.bucket,
          truncated: res.IsTruncated ?? false,
          count: res.KeyCount ?? 0,
          objects: (res.Contents ?? []).map((o) => ({ key: o.Key, sizeBytes: o.Size, lastModified: o.LastModified })),
        };
      },
    },
    {
      name: "get_bucket_region",
      description: "Return the region a bucket lives in (buckets are global-namespaced but region-homed).",
      risk: "read",
      inputSchema: { bucket: z.string().describe("Bucket name") },
      handler: async (args, ctx) => {
        const res = await s3(ctx).send(new GetBucketLocationCommand({ Bucket: args.bucket as string }));
        return { bucket: args.bucket, region: res.LocationConstraint || "us-east-1" };
      },
    },
  ];
}
