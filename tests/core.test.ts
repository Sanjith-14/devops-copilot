import { describe, it, expect } from "vitest";
import { Guardrails } from "../src/core/guardrails.js";
import { AwsClientFactory } from "../src/core/aws-client.js";
import { loadConfig } from "../src/core/config.js";
import type { CopilotConfig } from "../src/core/types.js";

const baseCfg: CopilotConfig = {
  defaultRegion: "ap-south-1",
  allowWrite: false,
  allowDestructive: false,
  enabledServices: "*",
};

const dummyCreds = async () => ({ accessKeyId: "x", secretAccessKey: "y" });

describe("Guardrails verdicts", () => {
  it("always allows read tools", () => {
    const g = new Guardrails(baseCfg);
    expect(g.decide("read", false).verdict).toBe("allow");
    expect(g.decide("read", true).verdict).toBe("allow");
  });

  it("mutate requires user confirmation when the client supports it", () => {
    const g = new Guardrails(baseCfg);
    expect(g.decide("mutate", true).verdict).toBe("confirm");
  });

  it("mutate without elicitation is denied unless env opts in", () => {
    expect(new Guardrails(baseCfg).decide("mutate", false).verdict).toBe("deny");
    expect(new Guardrails({ ...baseCfg, allowWrite: true }).decide("mutate", false).verdict).toBe("allow");
  });

  it("destructive is denied without the env gate, even with elicitation", () => {
    expect(new Guardrails(baseCfg).decide("destructive", true).verdict).toBe("deny");
  });

  it("destructive with env gate still requires confirmation", () => {
    const g = new Guardrails({ ...baseCfg, allowDestructive: true });
    expect(g.decide("destructive", true).verdict).toBe("confirm");
    expect(g.decide("destructive", false).verdict).toBe("deny");
  });
});

describe("Config from environment", () => {
  it("uses safe read-only defaults with an empty env", () => {
    const cfg = loadConfig({});
    expect(cfg.allowWrite).toBe(false);
    expect(cfg.allowDestructive).toBe(false);
    expect(cfg.defaultRegion).toBe("us-east-1");
    expect(cfg.profileAllowlist).toBeUndefined();
    expect(cfg.enabledServices).toBe("*");
  });

  it("parses allowlist, default profile, and gates", () => {
    const cfg = loadConfig({
      DEVOPS_COPILOT_PROFILES: "audit-portal-dev, prod",
      DEVOPS_COPILOT_DEFAULT_PROFILE: "audit-portal-dev",
      DEVOPS_COPILOT_ALLOW_WRITE: "true",
      AWS_REGION: "ap-south-1",
    });
    expect(cfg.profileAllowlist).toEqual(["audit-portal-dev", "prod"]);
    expect(cfg.defaultAccount).toBe("audit-portal-dev");
    expect(cfg.allowWrite).toBe(true);
    expect(cfg.defaultRegion).toBe("ap-south-1");
  });
});

describe("AwsClientFactory account resolution", () => {
  const f = new AwsClientFactory(baseCfg);
  f.registerEphemeralAccount({ id: "sandbox", profile: "default" }, dummyCreds);
  f.registerEphemeralAccount({ id: "prod", profile: "prod", defaultRegion: "us-east-1" }, dummyCreds);

  it("resolves a named account", () => {
    expect(f.resolveAccount("prod").defaultRegion).toBe("us-east-1");
  });

  it("rejects unknown accounts with a helpful message", () => {
    expect(() => f.resolveAccount("nope")).toThrow(/Known accounts: sandbox, prod/);
  });

  it("rejects duplicate account ids", () => {
    expect(() => f.registerEphemeralAccount({ id: "prod", profile: "" }, dummyCreds)).toThrow(/already exists/);
  });

  it("region precedence: explicit > account default > server default", () => {
    const prod = f.resolveAccount("prod");
    expect(f.resolveRegion(prod, "eu-west-1")).toBe("eu-west-1");
    expect(f.resolveRegion(prod)).toBe("us-east-1");
    expect(f.resolveRegion(f.resolveAccount("sandbox"))).toBe("ap-south-1");
  });
});
