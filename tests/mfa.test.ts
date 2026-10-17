import { describe, it, expect } from "vitest";
import {
  analyzeTrustPolicy,
  assumeRoleWithMfa,
  detectMfaSerial,
  parseCallerArn,
  refreshingRoleProvider,
  validateMfaCode,
  type MfaDeps,
} from "../src/core/mfa.js";
import { parseLoginArgs } from "../src/core/login.js";
import { memoizeCredentials, AwsClientFactory } from "../src/core/aws-client.js";

const USER_ARN = "arn:aws:iam::111122223333:user/alice";
const ROLE_ARN = "arn:aws:iam::444455556666:role/ReadOnly";
const SERIAL = "arn:aws:iam::111122223333:mfa/alice";
const LONG_TERM = async () => ({ accessKeyId: "AKIA", secretAccessKey: "s" });
const SESSION = async () => ({ accessKeyId: "ASIA", secretAccessKey: "s", sessionToken: "t" });
const inOneHour = () => new Date(Date.now() + 3600_000);
const stsCreds = (id: string, exp = inOneHour()) => ({ AccessKeyId: id, SecretAccessKey: "x", SessionToken: "y", Expiration: exp });

/**
 * Fake STS/IAM: responds by command name; `behavior` decides per call.
 * Records (command, input, caller access key) so tests can assert the flow.
 */
function fakeDeps(behavior: Record<string, (input: any, callerKey: string) => unknown>) {
  const calls: { cmd: string; input: any; caller: string }[] = [];
  const client = (creds: any) => ({
    async send(cmd: { constructor: { name: string }; input: any }) {
      const c = typeof creds === "function" ? await creds() : creds;
      const name = cmd.constructor.name.replace("Command", "");
      calls.push({ cmd: name, input: cmd.input, caller: c.accessKeyId });
      const fn = behavior[name];
      if (!fn) throw new Error(`unexpected ${name}`);
      const out = fn(cmd.input, c.accessKeyId);
      if (out instanceof Error) throw out;
      return out;
    },
  });
  const deps: MfaDeps = { sts: client, iam: client };
  return { deps, calls };
}

const denied = () => Object.assign(new Error("AccessDenied: not authorized to perform sts:AssumeRole"), { name: "AccessDenied" });

describe("caller + code parsing", () => {
  it("classifies caller ARNs", () => {
    expect(parseCallerArn(USER_ARN)).toMatchObject({ kind: "user", name: "alice", account: "111122223333" });
    expect(parseCallerArn("arn:aws:sts::111122223333:assumed-role/Admin/sess")).toMatchObject({
      kind: "assumed-role",
      name: "Admin",
      roleArn: "arn:aws:iam::111122223333:role/Admin",
    });
    expect(parseCallerArn("arn:aws:iam::111122223333:root").kind).toBe("root");
  });

  it("validates 6-digit codes", () => {
    expect(validateMfaCode(" 123 456 ")).toBe("123456");
    expect(() => validateMfaCode("12345")).toThrow(/6 digits/);
    expect(() => validateMfaCode("abcdef")).toThrow(/6 digits/);
  });
});

describe("MFA device detection", () => {
  const identity = { GetCallerIdentity: () => ({ Arn: USER_ARN }) };

  it("prefers the configured serial", async () => {
    const { deps } = fakeDeps(identity);
    expect(await detectMfaSerial(LONG_TERM, "us-east-1", { configuredSerial: "arn:x", deps })).toMatchObject({
      serial: "arn:x",
      source: "configured",
    });
  });

  it("finds the user's registered device via IAM", async () => {
    const { deps } = fakeDeps({ ...identity, ListMFADevices: () => ({ MFADevices: [{ SerialNumber: SERIAL }] }) });
    expect(await detectMfaSerial(LONG_TERM, "us-east-1", { deps })).toMatchObject({ serial: SERIAL, source: "iam" });
  });

  it("guesses mfa/<username> when listing is denied", async () => {
    const { deps } = fakeDeps({ ...identity, ListMFADevices: () => denied() });
    expect(await detectMfaSerial(LONG_TERM, "us-east-1", { deps })).toMatchObject({ serial: SERIAL, source: "guess" });
  });

  it("returns none for assumed-role callers", async () => {
    const { deps } = fakeDeps({ GetCallerIdentity: () => ({ Arn: "arn:aws:sts::1:assumed-role/R/s" }) });
    expect((await detectMfaSerial(SESSION, "us-east-1", { deps })).source).toBe("none");
  });
});

describe("assumeRoleWithMfa — MFA only if needed", () => {
  const base = { roleArn: ROLE_ARN, region: "us-east-1" };

  it("no MFA device: plain AssumeRole", async () => {
    const { deps, calls } = fakeDeps({ AssumeRole: () => ({ Credentials: stsCreds("ROLE") }) });
    const r = await assumeRoleWithMfa({ ...base, sourceCredentials: LONG_TERM, deps });
    expect(r).toMatchObject({ flow: "role", mfaUsed: false, credentials: { accessKeyId: "ROLE" } });
    expect(calls.map((c) => c.cmd)).toEqual(["AssumeRole"]);
  });

  it("device known but role doesn't need MFA: never asks for a code", async () => {
    let asked = 0;
    const { deps } = fakeDeps({ AssumeRole: () => ({ Credentials: stsCreds("ROLE") }) });
    const r = await assumeRoleWithMfa({ ...base, sourceCredentials: LONG_TERM, serial: SERIAL, getCode: async () => (asked++, "123456"), deps });
    expect(r.mfaUsed).toBe(false);
    expect(asked).toBe(0);
  });

  it("denied without MFA + long-term keys: one code -> MFA session -> role from that session", async () => {
    const codes: string[] = [];
    const { deps, calls } = fakeDeps({
      AssumeRole: (_i, caller) => (caller === "SESSION" ? { Credentials: stsCreds("ROLE") } : denied()),
      GetSessionToken: () => ({ Credentials: stsCreds("SESSION", new Date(Date.now() + 12 * 3600_000)) }),
    });
    const r = await assumeRoleWithMfa({
      ...base,
      sourceCredentials: LONG_TERM,
      serial: SERIAL,
      getCode: async (serial) => (codes.push(serial), "123456"),
      deps,
    });
    expect(r).toMatchObject({ flow: "mfa-session-then-role", mfaUsed: true, credentials: { accessKeyId: "ROLE" } });
    expect(codes).toEqual([SERIAL]);
    expect(calls.map((c) => `${c.cmd}@${c.caller}`)).toEqual(["AssumeRole@AKIA", "GetSessionToken@AKIA", "AssumeRole@SESSION"]);
    expect(calls[1].input).toMatchObject({ SerialNumber: SERIAL, TokenCode: "123456" });
    // The role call from the MFA session must not reuse the single-use code.
    expect(calls[2].input.TokenCode).toBeUndefined();
  });

  it("mfaRequired skips the no-MFA attempt", async () => {
    const { deps, calls } = fakeDeps({
      AssumeRole: () => ({ Credentials: stsCreds("ROLE") }),
      GetSessionToken: () => ({ Credentials: stsCreds("SESSION") }),
    });
    await assumeRoleWithMfa({ ...base, sourceCredentials: LONG_TERM, serial: SERIAL, mfaRequired: true, getCode: async () => "111111", deps });
    expect(calls.map((c) => c.cmd)).toEqual(["GetSessionToken", "AssumeRole"]);
  });

  it("session-credential source: one-step AssumeRole with MFA after a denial", async () => {
    const { deps, calls } = fakeDeps({
      AssumeRole: (i) => (i.TokenCode ? { Credentials: stsCreds("ROLE") } : denied()),
    });
    const r = await assumeRoleWithMfa({ ...base, sourceCredentials: SESSION, serial: SERIAL, getCode: async () => "222222", deps });
    expect(r.flow).toBe("role-with-mfa");
    expect(calls[1].input).toMatchObject({ SerialNumber: SERIAL, TokenCode: "222222" });
  });

  it("GetSessionToken not permitted: asks for a FRESH code and does one-step AssumeRole", async () => {
    const codes = ["111111", "222222"];
    const { deps, calls } = fakeDeps({
      AssumeRole: (i) => (i.TokenCode ? { Credentials: stsCreds("ROLE") } : denied()),
      GetSessionToken: () => denied(),
    });
    const r = await assumeRoleWithMfa({ ...base, sourceCredentials: LONG_TERM, serial: SERIAL, getCode: async () => codes.shift()!, deps });
    expect(r.flow).toBe("role-with-mfa");
    expect(calls.at(-1)!.input.TokenCode).toBe("222222");
  });

  it("wrong code surfaces the error (no silent retries)", async () => {
    const { deps } = fakeDeps({
      AssumeRole: () => denied(),
      GetSessionToken: () => new Error("AccessDenied: MultiFactorAuthentication failed with invalid MFA one time pass code."),
    });
    await expect(
      assumeRoleWithMfa({ ...base, sourceCredentials: LONG_TERM, serial: SERIAL, getCode: async () => "000000", deps }),
    ).rejects.toThrow(/MultiFactorAuthentication failed/);
  });

  it("denied with no MFA device hints at MFA", async () => {
    const { deps } = fakeDeps({ AssumeRole: () => denied() });
    await expect(assumeRoleWithMfa({ ...base, sourceCredentials: LONG_TERM, deps })).rejects.toThrow(/may require MFA/);
  });
});

describe("refreshingRoleProvider", () => {
  it("re-mints role creds from the MFA session without asking for a code", async () => {
    let asked = 0;
    const { deps, calls } = fakeDeps({ AssumeRole: () => ({ Credentials: stsCreds("ROLE2") }) });
    const provider = refreshingRoleProvider(
      { roleArn: ROLE_ARN, region: "us-east-1", sourceCredentials: LONG_TERM, serial: SERIAL, getCode: async () => (asked++, "1"), deps },
      {
        credentials: { accessKeyId: "ROLE1", secretAccessKey: "x", expiration: new Date(Date.now() + 60_000) }, // expiring
        mfaSession: { accessKeyId: "SESSION", secretAccessKey: "x", sessionToken: "t", expiration: new Date(Date.now() + 6 * 3600_000) },
        flow: "mfa-session-then-role",
        mfaUsed: true,
      },
    );
    const [a, b] = await Promise.all([provider(), provider()]);
    expect(a.accessKeyId).toBe("ROLE2");
    expect(b.accessKeyId).toBe("ROLE2");
    expect(calls).toHaveLength(1); // single in-flight refresh
    expect(calls[0].caller).toBe("SESSION");
    expect(asked).toBe(0);
  });
});

describe("trust policy analysis", () => {
  const caller = parseCallerArn(USER_ARN);
  const policy = (principal: unknown, condition?: unknown) =>
    encodeURIComponent(
      JSON.stringify({ Statement: [{ Effect: "Allow", Principal: principal, Action: "sts:AssumeRole", ...(condition ? { Condition: condition } : {}) }] }),
    );

  it("detects direct trust with MFA condition", () => {
    expect(analyzeTrustPolicy(policy({ AWS: USER_ARN }, { Bool: { "aws:MultiFactorAuthPresent": "true" } }), caller)).toEqual({
      trusted: true,
      via: "you",
      mfaRequired: true,
      externalIdRequired: false,
    });
  });

  it("detects account-root trust and ExternalId", () => {
    const t = analyzeTrustPolicy(policy({ AWS: ["arn:aws:iam::111122223333:root"] }, { StringEquals: { "sts:ExternalId": "x" } }), caller);
    expect(t).toMatchObject({ trusted: true, via: "your-account", externalIdRequired: true, mfaRequired: false });
  });

  it("ignores service principals, other accounts and Deny", () => {
    expect(analyzeTrustPolicy(policy({ Service: "lambda.amazonaws.com" }), caller).trusted).toBe(false);
    expect(analyzeTrustPolicy(policy({ AWS: "arn:aws:iam::999999999999:root" }), caller).trusted).toBe(false);
    const deny = encodeURIComponent(JSON.stringify({ Statement: { Effect: "Deny", Principal: { AWS: USER_ARN }, Action: "sts:AssumeRole" } }));
    expect(analyzeTrustPolicy(deny, caller).trusted).toBe(false);
    expect(analyzeTrustPolicy("not json", caller).trusted).toBe(false);
  });

  it("matches the underlying role for assumed-role callers", () => {
    const roleCaller = parseCallerArn("arn:aws:sts::111122223333:assumed-role/Admin/s");
    expect(analyzeTrustPolicy(policy({ AWS: "arn:aws:iam::111122223333:role/Admin" }), roleCaller).via).toBe("you");
  });
});

describe("login argument parsing", () => {
  it("defaults to AWS_PROFILE / default and a 12h session", () => {
    expect(parseLoginArgs([], {})).toMatchObject({ profile: "default", durationSeconds: 12 * 3600 });
    expect(parseLoginArgs([], { AWS_PROFILE: "work" }).profile).toBe("work");
    expect(parseLoginArgs(["--profile", "x", "--duration-hours", "2", "--mfa-serial", SERIAL], {})).toMatchObject({
      profile: "x",
      durationSeconds: 7200,
      mfaSerial: SERIAL,
    });
  });

  it("rejects unknown flags and bad durations", () => {
    expect(() => parseLoginArgs(["--password", "x"], {})).toThrow(/Unknown option/);
    expect(() => parseLoginArgs(["--duration-hours", "abc"], {})).toThrow(/positive/);
  });
});

describe("credential memoization", () => {
  it("resolves once for concurrent callers, refreshes near expiry", async () => {
    let n = 0;
    const p = memoizeCredentials(async () => ({ accessKeyId: `K${++n}`, secretAccessKey: "s", expiration: new Date(Date.now() + 60_000) }));
    const [a, b] = await Promise.all([p(), p()]);
    expect([a.accessKeyId, b.accessKeyId]).toEqual(["K1", "K1"]);
    expect((await p()).accessKeyId).toBe("K2"); // within 5-minute margin -> refresh
  });

  it("re-assuming a role replaces only ephemeral accounts", () => {
    const f = new AwsClientFactory({ defaultRegion: "us-east-1", allowWrite: false, allowDestructive: false, enabledServices: "*" });
    f.registerEphemeralAccount({ id: "prod-ro", profile: "" }, LONG_TERM);
    expect(() => f.registerEphemeralAccount({ id: "prod-ro", profile: "" }, LONG_TERM)).toThrow(/already exists/);
    expect(() => f.registerEphemeralAccount({ id: "prod-ro", profile: "" }, LONG_TERM, { replace: true })).not.toThrow();
  });
});
