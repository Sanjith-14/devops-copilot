import { describe, it, expect } from "vitest";
import createMonitorModule from "../src/services/monitor/index.js";
import createCostModule from "../src/services/cost/index.js";
import { AwsClientFactory } from "../src/core/aws-client.js";
import type { CopilotConfig } from "../src/core/types.js";

const cfg: CopilotConfig = {
  defaultRegion: "ap-south-1",
  allowWrite: false,
  allowDestructive: false,
  enabledServices: "*",
};

const factory = new AwsClientFactory(cfg);

describe("Monitor module contract", () => {
  const mod = createMonitorModule(factory);

  it("exposes the expected tools", () => {
    expect(mod.name).toBe("monitor");
    expect(mod.tools.map((t) => t.name)).toEqual(["run_checks", "check_asg_instances", "check_alarms"]);
  });

  it("is read-only: every tool declares read risk", () => {
    for (const tool of mod.tools) expect(tool.risk).toBe("read");
  });
});

describe("Cost module contract", () => {
  const mod = createCostModule(factory);

  it("exposes the expected tools", () => {
    expect(mod.name).toBe("cost");
    expect(mod.tools.map((t) => t.name)).toEqual(["daily_spend", "detect_spend_spikes", "get_aws_anomalies"]);
  });

  it("is read-only: every tool declares read risk", () => {
    for (const tool of mod.tools) expect(tool.risk).toBe("read");
  });
});
