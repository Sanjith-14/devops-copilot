import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtempSync, writeFileSync, readFileSync, utimesSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { upsertIniSection, loadAwsFiles } from "../src/core/aws-files.js";
import { cachedMfaSession, getRoleCredentials, roleRows, ACTIVE_PROFILE } from "../src/core/roles.js";
import { AwsClientFactory, describeProfile } from "../src/core/aws-client.js";
import type { MfaDeps } from "../src/core/mfa.js";

const ROLE = "arn:aws:iam::444455556666:role/ReadOnly";
const SERIAL = "arn:aws:iam::111122223333:mfa/alice";
const later = (h: number) => new Date(Date.now() + h * 3600_000);

let dir: string;
let configPath: string;
let credsPath: string;
const saved = { config: process.env.AWS_CONFIG_FILE, creds: process.env.AWS_SHARED_CREDENTIALS_FILE };

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "copilot-roles-"));
  configPath = join(dir, "config");
  credsPath = join(dir, "credentials");
  process.env.AWS_CONFIG_FILE = configPath;
  process.env.AWS_SHARED_CREDENTIALS_FILE = credsPath;
  writeFileSync(configPath, `[profile work]\nregion = ap-south-1\n\n[profile prod-ro]\nrole_arn = ${ROLE}\nsource_profile = work\nmfa_serial = ${SERIAL}\n`);
  writeFileSync(credsPath, "[work]\naws_access_key_id = AKIAWORK\naws_secret_access_key = secret\n");
});
afterEach(() => {
  process.env.AWS_CONFIG_FILE = saved.config;
  process.env.AWS_SHARED_CREDENTIALS_FILE = saved.creds;
  rmSync(dir, { recursive: true, force: true });
});

/** Fake STS: long-term keys are denied AssumeRole (force-MFA policy); MFA sessions are allowed. */
function fakeSts() {
  const calls: string[] = [];
  const deps: MfaDeps = {
    iam: () => ({ send: async () => ({}) }),
    sts: (creds: any) => ({
      async send(cmd: { constructor: { name: string }; input: any }) {
        const c = typeof creds === "function" ? await creds() : creds;
        const name = cmd.constructor.name.replace("Command", "");
        calls.push(`${name}@${c.accessKeyId}`);
        if (name === "GetSessionToken") {
          return { Credentials: { AccessKeyId: "ASIASESSION", SecretAccessKey: "s", SessionToken: "t", Expiration: later(12) } };
        }
        if (name === "AssumeRole") {
          if (c.accessKeyId === "AKIAWORK" && !cmd.input.TokenCode) throw new Error("AccessDenied: explicit deny (MFA policy)");
          return { Credentials: { AccessKeyId: "ASIAROLE", SecretAccessKey: "s", SessionToken: "t", Expiration: later(1) } };
        }
        throw new Error(`unexpected ${name}`);
      },
    }),
  };
  return { deps, calls };
}

describe("ini writing", () => {
  it("replaces only the exact section (names with dots/spaces are escaped)", () => {
    const before = "[profile prod.ro]\nrole_arn = A\n\n[profile prodXro]\nrole_arn = KEEP\n";
    const out = upsertIniSection(before, "profile prod.ro", "role_arn = B");
    expect(out).toContain("role_arn = B");
    expect(out).toContain("role_arn = KEEP");
    expect(out).not.toContain("role_arn = A");
  });
});

describe("role use: one code per day, then free switching", () => {
  it("first use asks for ONE code, caches the MFA session; second use asks for none", async () => {
    let codes = 0;
    const getCode = async () => (codes++, "123456");

    const s1 = fakeSts();
    const r1 = await getRoleCredentials("prod-ro", { getCode, deps: s1.deps });
    expect(r1).toMatchObject({ roleArn: ROLE, mfaUsed: true, usedCachedSession: false, credentials: { accessKeyId: "ASIAROLE" } });
    expect(codes).toBe(1);
    expect(s1.calls).toEqual(["AssumeRole@AKIAWORK", "GetSessionToken@AKIAWORK", "AssumeRole@ASIASESSION"]);

    // The MFA session was saved for reuse (tagged with its source + expiry).
    const creds = readFileSync(credsPath, "utf8");
    expect(creds).toMatch(/\[copilot-session\][\s\S]*copilot_source_profile = work/);
    expect(creds).toContain("[work]"); // original profile untouched

    const s2 = fakeSts();
    const r2 = await getRoleCredentials("prod-ro", { getCode, deps: s2.deps });
    expect(r2.usedCachedSession).toBe(true);
    expect(codes).toBe(1); // no new code
    expect(s2.calls).toEqual(["AssumeRole@ASIASESSION"]);
  });

  it("explains unknown roles", async () => {
    await expect(getRoleCredentials("nope", { getCode: async () => "1", deps: fakeSts().deps })).rejects.toThrow(
      /role add nope <role-arn>/,
    );
  });
});

describe("cached session + listing", () => {
  it("only reuses a valid session from the same source profile", async () => {
    const files = await loadAwsFiles();
    const session = (src: string, exp: Date) => ({
      ...files,
      credentials: {
        ...files.credentials,
        "copilot-session": { aws_access_key_id: "A", aws_secret_access_key: "B", aws_session_token: "C", copilot_source_profile: src, copilot_expiration: exp.toISOString() },
      },
    });
    expect(cachedMfaSession(session("work", later(2)), "work")?.accessKeyId).toBe("A");
    expect(cachedMfaSession(session("other", later(2)), "work")).toBeUndefined();
    expect(cachedMfaSession(session("work", later(0.01)), "work")).toBeUndefined(); // < 5 min left
  });

  it("role list marks the active role", async () => {
    writeFileSync(credsPath, readFileSync(credsPath, "utf8") + `\n[${ACTIVE_PROFILE}]\naws_access_key_id = X\naws_secret_access_key = Y\ncopilot_role = prod-ro\ncopilot_expiration = ${later(1).toISOString()}\n`);
    expect(roleRows(await loadAwsFiles())).toEqual([
      { name: "prod-ro", active: true, roleArn: ROLE, source: "work", mfa: true, mfaSessionValid: false },
    ]);
  });

  it("describes profiles for list_accounts", () => {
    expect(describeProfile(ACTIVE_PROFILE, { copilot_role: "prod-ro", copilot_role_arn: ROLE, copilot_expiration: later(1).toISOString() })).toMatch(
      /^Active role "prod-ro" .* until .* role use/,
    );
    expect(describeProfile("prod-ro", { role_arn: ROLE, source_profile: "work", mfa_serial: SERIAL })).toBe(
      `Role ${ROLE} via "work" (MFA if needed)`,
    );
  });
});

describe("server hot-reload", () => {
  it("picks up profiles written while running; keeps a switched default", async () => {
    const f = new AwsClientFactory({ defaultRegion: "us-east-1", allowWrite: false, allowDestructive: false, enabledServices: "*" });
    await f.discoverAccounts();
    expect(f.listAccounts().map((a) => a.id).sort()).toEqual(["prod-ro", "work"]);
    f.setDefaultAccount("prod-ro");
    expect(await f.refreshIfChanged()).toBe(false);

    // Simulate `devops-copilot role use prod-ro` in another terminal.
    writeFileSync(credsPath, readFileSync(credsPath, "utf8") + `\n[${ACTIVE_PROFILE}]\naws_access_key_id = X\naws_secret_access_key = Y\ncopilot_role = prod-ro\n`);
    const t = new Date(Date.now() + 5000);
    utimesSync(credsPath, t, t);

    expect(await f.refreshIfChanged()).toBe(true);
    expect(f.listAccounts().map((a) => a.id)).toContain(ACTIVE_PROFILE);
    expect(f.defaultAccount()).toBe("prod-ro");
  });
});
