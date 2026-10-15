import { describe, it, expect, vi } from "vitest";
import { readdirSync, existsSync } from "node:fs";
import { join } from "node:path";
import { RECIPES, renderRecipe } from "../src/core/prompts.js";
import { audit } from "../src/core/runner.js";
import { bestEffort, withTimeout, TimeoutError } from "../src/core/helpers.js";
import { loadMarkdownTools } from "../src/core/md-tools.js";
import { fakeFactory } from "./fake-aws.js";

/** Every tool name the server would expose (TS + markdown), built like the registry does. */
async function allToolNames(): Promise<Set<string>> {
  const { factory } = fakeFactory({});
  const dir = join(__dirname, "..", "src", "services");
  const names = new Set<string>();
  for (const mod of readdirSync(dir)) {
    const idx = join(dir, mod, "index.ts");
    if (existsSync(idx)) {
      const m = (await import(idx)).default(factory);
      for (const t of m.tools) names.add(`${m.name}_${t.name}`);
    }
    for (const t of await loadMarkdownTools(join(dir, mod), factory)) names.add(`${mod}_${t.name}`);
  }
  return names;
}

describe("MCP prompts", () => {
  it("every recipe step names a real tool", async () => {
    const names = await allToolNames();
    for (const r of RECIPES) for (const s of r.steps) expect(names, `${r.name} -> ${s.tool}`).toContain(s.tool);
  });

  it("renders only loaded tools and the user's arguments", () => {
    const triage = RECIPES.find((r) => r.name === "incident_triage")!;
    const text = renderRecipe(triage, { symptom: "502 on api", account: "prod" }, new Set(["cloudtrail_recent_changes"]));
    expect(text).toContain('"502 on api"');
    expect(text).toContain('account "prod"');
    expect(text).toContain("1. `cloudtrail_recent_changes`");
    expect(text).not.toContain("ecs_service_health");
    expect(text).toMatch(/do NOT perform any changes/);
  });
});

describe("runner + helpers", () => {
  it("audit writes one JSON line with arg NAMES only", () => {
    const spy = vi.spyOn(console, "error").mockImplementation(() => {});
    audit({ tool: "s3_list_objects", account: "dev", args: { bucket: "secret-bucket", prefix: undefined }, ms: 12, outcome: "ok" });
    const line = JSON.parse(spy.mock.calls[0][0] as string);
    spy.mockRestore();
    expect(line).toMatchObject({ audit: "tool_call", tool: "s3_list_objects", account: "dev", argNames: ["bucket"], outcome: "ok", ms: 12 });
    expect(JSON.stringify(line)).not.toContain("secret-bucket");
  });

  it("withTimeout rejects slow calls with a helpful message", async () => {
    await expect(withTimeout(new Promise(() => {}), 20, "slow_tool")).rejects.toBeInstanceOf(TimeoutError);
    await expect(withTimeout(Promise.resolve(1), 1000, "fast")).resolves.toBe(1);
  });

  it("bestEffort turns AccessDenied into a skipped section", async () => {
    expect(await bestEffort(async () => 5)).toEqual({ status: "checked", data: 5 });
    const r = await bestEffort(async () => {
      throw new Error("AccessDeniedException: User is not authorized");
    });
    expect(r).toMatchObject({ status: "skipped", reason: expect.stringMatching(/^no permission/) });
  });
});
