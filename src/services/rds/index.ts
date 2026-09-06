import { RDSClient, DescribeDBInstancesCommand } from "@aws-sdk/client-rds";
import type { ServiceModule, ServiceModuleFactory } from "../../core/types.js";
import { buildRdsTools } from "./tools.js";

/** Amazon RDS: instance inventory with security posture, health metrics. */
const createRdsModule: ServiceModuleFactory = (factory) => {
  const mod: ServiceModule = {
    name: "rds",
    description: "Amazon RDS: DB instance inventory (status, encryption, public exposure) and health metrics.",
    tools: buildRdsTools(factory),
    healthCheck: async (ctx) => {
      try {
        const { client } = factory.getClient(RDSClient, ctx.accountId, ctx.region);
        await client.send(new DescribeDBInstancesCommand({ MaxRecords: 20 }));
        return { ok: true };
      } catch (err) {
        return { ok: false, detail: String(err) };
      }
    },
  };
  return mod;
};

export default createRdsModule;
