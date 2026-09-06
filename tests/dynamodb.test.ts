import { describe, it, expect } from "vitest";
import createDynamoDbModule from "../src/services/dynamodb/index.js";
import { AwsClientFactory } from "../src/core/aws-client.js";
import type { CopilotConfig } from "../src/core/types.js";

const cfg: CopilotConfig = {
  defaultRegion: "ap-south-1",
  allowWrite: false,
  allowDestructive: false,
  enabledServices: "*",
};

describe("DynamoDB module contract", () => {
  const mod = createDynamoDbModule(new AwsClientFactory(cfg));

  it("exposes the expected tools", () => {
    expect(mod.name).toBe("dynamodb");
    expect(mod.tools.map((t) => t.name)).toEqual([
      "list_tables",
      "describe_table",
      "check_table_throttling",
    ]);
  });

  it("is read-only: every tool declares read risk", () => {
    for (const tool of mod.tools) expect(tool.risk).toBe("read");
  });

  it("every tool has a description and handler", () => {
    for (const tool of mod.tools) {
      expect(tool.description.length).toBeGreaterThan(10);
      expect(typeof tool.handler).toBe("function");
    }
  });
});
