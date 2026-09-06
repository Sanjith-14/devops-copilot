import { DynamoDBClient, ListTablesCommand } from "@aws-sdk/client-dynamodb";
import type { ServiceModule, ServiceModuleFactory } from "../../core/types.js";
import { buildDynamoDbTools } from "./tools.js";

/** Amazon DynamoDB: table inventory, details, throttle checks. */
const createDynamoDbModule: ServiceModuleFactory = (factory) => {
  const mod: ServiceModule = {
    name: "dynamodb",
    description: "Amazon DynamoDB: table inventory, table details (billing, capacity, indexes), throttle checks.",
    tools: buildDynamoDbTools(factory),
    healthCheck: async (ctx) => {
      try {
        const { client } = factory.getClient(DynamoDBClient, ctx.accountId, ctx.region);
        await client.send(new ListTablesCommand({ Limit: 1 }));
        return { ok: true };
      } catch (err) {
        return { ok: false, detail: String(err) };
      }
    },
  };
  return mod;
};

export default createDynamoDbModule;
