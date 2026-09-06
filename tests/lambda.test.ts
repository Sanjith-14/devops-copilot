import { describe, it, expect } from "vitest";
import createLambdaModule from "../src/services/lambda/index.js";
import { AwsClientFactory } from "../src/core/aws-client.js";
import type { CopilotConfig } from "../src/core/types.js";

const cfg: CopilotConfig = {
  defaultRegion: "ap-south-1",
  allowWrite: false,
  allowDestructive: false,
  enabledServices: "*",
};

describe("Lambda module contract", () => {
  const mod = createLambdaModule(new AwsClientFactory(cfg));

  it("exposes the expected tools", () => {
    expect(mod.name).toBe("lambda");
    expect(mod.tools.map((t) => t.name)).toEqual([
      "list_functions",
      "get_function_config",
      "function_errors",
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
