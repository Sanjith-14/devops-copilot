import { describe, it, expect } from "vitest";
import createCloudWatchModule from "../src/services/cloudwatch/index.js";
import { AwsClientFactory } from "../src/core/aws-client.js";
import type { CopilotConfig } from "../src/core/types.js";

const cfg: CopilotConfig = {
  defaultRegion: "ap-south-1",
  allowWrite: false,
  allowDestructive: false,
  enabledServices: "*",
};

describe("CloudWatch module contract", () => {
  const mod = createCloudWatchModule(new AwsClientFactory(cfg));

  it("exposes the expected tools", () => {
    expect(mod.name).toBe("cloudwatch");
    expect(mod.tools.map((t) => t.name)).toEqual([
      "list_log_groups",
      "tail_log_group",
      "list_alarms",
      "get_alarm_history",
      "list_metrics",
      "get_metric_statistics",
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
