import { S3Client, ListBucketsCommand } from "@aws-sdk/client-s3";
import type { ServiceModule, ServiceModuleFactory } from "../../core/types.js";
import { buildS3Tools } from "./tools.js";

/**
 * S3 service module. The default export is a factory function: the registry
 * calls it with the shared AwsClientFactory and gets a ServiceModule back.
 * This is the entire contract for adding a new AWS service.
 */
const createS3Module: ServiceModuleFactory = (factory) => {
  const mod: ServiceModule = {
    name: "s3",
    description: "Amazon S3: bucket inventory, security posture (public access, encryption), object listing.",
    tools: buildS3Tools(factory),
    healthCheck: async (ctx) => {
      try {
        const { client } = factory.getClient(S3Client, ctx.accountId, ctx.region);
        await client.send(new ListBucketsCommand({}));
        return { ok: true };
      } catch (err) {
        return { ok: false, detail: String(err) };
      }
    },
  };
  return mod;
};

export default createS3Module;
