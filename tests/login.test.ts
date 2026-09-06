import { describe, it, expect } from "vitest";
import { upsertIniSection, SESSION_PROFILE } from "../src/core/login.js";

describe("upsertIniSection", () => {
  const body = "aws_access_key_id = NEW\naws_secret_access_key = S";

  it("appends the section to an empty file", () => {
    const out = upsertIniSection("", SESSION_PROFILE, body);
    expect(out).toBe(`[${SESSION_PROFILE}]\n${body}\n`);
  });

  it("appends after existing sections without touching them", () => {
    const existing = "[default]\naws_access_key_id = KEEP\n";
    const out = upsertIniSection(existing, SESSION_PROFILE, body);
    expect(out).toContain("aws_access_key_id = KEEP");
    expect(out.indexOf("[default]")).toBeLessThan(out.indexOf(`[${SESSION_PROFILE}]`));
  });

  it("replaces an existing session section in place, preserving neighbors", () => {
    const existing = `[default]\nkey = KEEP\n\n[${SESSION_PROFILE}]\naws_access_key_id = OLD\n\n[other]\nkey = ALSO-KEEP\n`;
    const out = upsertIniSection(existing, SESSION_PROFILE, body);
    expect(out).not.toContain("OLD");
    expect(out).toContain("NEW");
    expect(out).toContain("KEEP");
    expect(out).toContain("ALSO-KEEP");
    expect(out.match(new RegExp(`\\[${SESSION_PROFILE}\\]`, "g"))).toHaveLength(1);
  });
});
