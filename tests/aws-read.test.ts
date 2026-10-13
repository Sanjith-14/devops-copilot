import { describe, it, expect } from "vitest";
import createAwsModule from "../src/services/aws/index.js";
import { AwsClientFactory } from "../src/core/aws-client.js";
import type { CopilotConfig, ToolContext } from "../src/core/types.js";

const cfg: CopilotConfig = {
  defaultRegion: "ap-south-1",
  allowWrite: false,
  allowDestructive: false,
  enabledServices: "*",
};
const ctx: ToolContext = { accountId: "test", region: "ap-south-1" };

describe("aws_read generic tool", () => {
  const mod = createAwsModule(new AwsClientFactory(cfg));
  const read = mod.tools[0];

  it("is exposed as aws_read with read risk", () => {
    expect(mod.name).toBe("aws");
    expect(read.name).toBe("read");
    expect(read.risk).toBe("read");
  });

  // These all fail BEFORE any AWS call or credential lookup.
  it("refuses write operations", async () => {
    await expect(read.handler({ service: "ec2", operation: "TerminateInstances" }, ctx)).rejects.toThrow(
      /not read-only/,
    );
    await expect(read.handler({ service: "s3", operation: "DeleteBucket" }, ctx)).rejects.toThrow(/not read-only/);
  });

  it("refuses secret-returning operations", async () => {
    await expect(
      read.handler({ service: "secrets-manager", operation: "GetSecretValue" }, ctx),
    ).rejects.toThrow(/blocked/);
    await expect(read.handler({ service: "ssm", operation: "GetParameter" }, ctx)).rejects.toThrow(/blocked/);
  });

  it("refuses malformed service names and unknown operations", async () => {
    await expect(read.handler({ service: "../../etc", operation: "ListThings" }, ctx)).rejects.toThrow(
      /Invalid service/,
    );
    await expect(read.handler({ service: "ec2", operation: "DescribeUnicorns" }, ctx)).rejects.toThrow(
      /no operation/,
    );
  });
});
