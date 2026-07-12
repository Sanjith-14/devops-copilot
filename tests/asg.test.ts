import { describe, it, expect } from "vitest";
import createAsgModule from "../src/services/asg/index.js";
import { AwsClientFactory } from "../src/core/aws-client.js";
import type { CopilotConfig } from "../src/core/types.js";

const cfg: CopilotConfig = {
  defaultRegion: "ap-south-1",
  allowWrite: false,
  allowDestructive: false,
  enabledServices: "*",
};

describe("ASG module contract", () => {
  const mod = createAsgModule(new AwsClientFactory(cfg));

  it("exposes the expected tools", () => {
    expect(mod.name).toBe("asg");
    expect(mod.tools.map((t) => t.name)).toEqual([
      "list_groups",
      "describe_group",
      "list_instances",
      "list_scaling_policies",
      "list_scaling_activities",
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
