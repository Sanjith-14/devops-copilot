import { describe, it, expect } from "vitest";
import createRdsModule from "../src/services/rds/index.js";
import { AwsClientFactory } from "../src/core/aws-client.js";
import type { CopilotConfig } from "../src/core/types.js";

const cfg: CopilotConfig = {
  defaultRegion: "ap-south-1",
  allowWrite: false,
  allowDestructive: false,
  enabledServices: "*",
};

describe("RDS module contract", () => {
  const mod = createRdsModule(new AwsClientFactory(cfg));

  it("exposes the expected tools", () => {
    expect(mod.name).toBe("rds");
    expect(mod.tools.map((t) => t.name)).toEqual(["list_db_instances", "get_db_metrics"]);
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
