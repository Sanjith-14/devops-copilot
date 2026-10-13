import jmespath from "jmespath";

/**
 * Shared plumbing for "declarative" AWS calls — markdown tools and the generic
 * aws_read tool. Everything here is a deterministic code-level guardrail: the
 * LLM (or a markdown author) can name an operation, but only this code decides
 * whether it is allowed to run.
 */

/** Operation-name prefixes that are read-only by AWS API convention. */
const READ_PREFIXES = ["Describe", "List", "Get", "Search", "Lookup"];

/**
 * Read-shaped operations that still return secrets or customer data. Blocked
 * even though their names look harmless. Dedicated tools (e.g.
 * lambda_get_function_config) cover the safe subset of these.
 */
const SENSITIVE_OPERATIONS = new Set([
  "GetSecretValue", // secretsmanager
  "BatchGetSecretValue",
  "GetParameter", // ssm (WithDecryption)
  "GetParameters",
  "GetParametersByPath",
  "GetObject", // s3 object data
  "GetObjectTorrent",
  "GetPasswordData", // ec2 Windows admin password
  "GetAuthorizationToken", // ecr docker login token
  "GetSessionToken", // sts
  "GetFederationToken",
  "GetFunction", // lambda: env values + presigned code URL
  "GetFunctionConfiguration",
  "GetItem", // dynamodb data plane
  "BatchGetItem",
  "GetRecords", // kinesis data
  "GetQueryResults", // athena result rows
  "GetLogEvents", // raw logs — use cloudwatch/lambda tools (truncated)
  "GetCredentialReport",
]);

export function isReadOperation(operation: string): boolean {
  return READ_PREFIXES.some((p) => operation.startsWith(p) && /^[A-Z]/.test(operation.slice(p.length)));
}

/** Throws unless `operation` is read-only and not on the sensitive denylist. */
export function assertReadAllowed(operation: string): void {
  if (!/^[A-Z][A-Za-z0-9]+$/.test(operation)) {
    throw new Error(`Invalid operation name "${operation}" (expected PascalCase, e.g. DescribeVpcs).`);
  }
  if (!isReadOperation(operation)) {
    throw new Error(
      `Operation "${operation}" is not read-only. Only ${READ_PREFIXES.join("/")}* operations are allowed here.`,
    );
  }
  if (SENSITIVE_OPERATIONS.has(operation)) {
    throw new Error(`Operation "${operation}" returns secrets or customer data and is blocked.`);
  }
}

type ClientCtor = new (config: never) => { send(command: unknown): Promise<unknown> };
type CommandCtor = new (input: Record<string, unknown>) => unknown;

/**
 * Resolve `@aws-sdk/client-<service>` and its `<Operation>Command` at runtime.
 * Throws a clear message when the package isn't installed or the operation
 * doesn't exist (the LLM can then correct itself).
 */
export async function loadSdkCommand(
  service: string,
  operation: string,
): Promise<{ Client: ClientCtor; Command: CommandCtor }> {
  if (!/^[a-z0-9-]+$/.test(service)) throw new Error(`Invalid service name "${service}" (e.g. "ec2", "ecs").`);
  const pkg = `@aws-sdk/client-${service}`;
  let mod: Record<string, unknown>;
  try {
    mod = (await import(pkg)) as Record<string, unknown>;
  } catch {
    throw new Error(`AWS SDK package ${pkg} is not installed. Install it with: npm install ${pkg}`);
  }
  const clientName = Object.keys(mod).find((k) => k.endsWith("Client") && !k.startsWith("_"));
  const Command = mod[`${operation}Command`];
  if (!clientName) throw new Error(`${pkg} exports no client class.`);
  if (typeof Command !== "function") throw new Error(`${pkg} has no operation "${operation}".`);
  return { Client: mod[clientName] as ClientCtor, Command: Command as CommandCtor };
}

/** Keys whose values are masked anywhere in a response. */
const SECRET_KEY = /(password|secret|privatekey|credentials?|sessiontoken|accesskey|authtoken)/i;
const SAFE_SUFFIX = /(arn|id|name|enabled|status|type|kmskeyid)$/i;

/**
 * Recursively mask secret-looking values: credential-ish keys, Lambda
 * `Environment.Variables` values, and ECS-style `environment: [{name, value}]`.
 */
export function redact(value: unknown, key = ""): unknown {
  if (Array.isArray(value)) {
    if (/^environment$/i.test(key)) {
      return value.map((e) =>
        e && typeof e === "object" && "value" in e ? { ...e, value: "[redacted]" } : redact(e),
      );
    }
    return value.map((v) => redact(v));
  }
  if (value === null || typeof value !== "object") {
    if (key && SECRET_KEY.test(key) && !SAFE_SUFFIX.test(key) && typeof value === "string") {
      return "[redacted]";
    }
    return value;
  }
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
    if (k === "$metadata") continue;
    if (k === "Variables" && v && typeof v === "object" && !Array.isArray(v)) {
      out[k] = Object.fromEntries(Object.keys(v).map((name) => [name, "[redacted]"]));
      continue;
    }
    out[k] = redact(v, k);
  }
  return out;
}

const PAGINATION_KEYS = ["NextToken", "nextToken", "Marker", "NextMarker", "NextContinuationToken"];

/**
 * Turn a raw SDK response into an LLM-sized result: redact, project with an
 * optional JMESPath expression, cap list length, and flag more pages.
 */
export function shapeOutput(
  response: unknown,
  opts: { output?: string; limit?: number },
): Record<string, unknown> {
  const raw = (response ?? {}) as Record<string, unknown>;
  const moreAvailable = PAGINATION_KEYS.some((k) => raw[k] != null) || undefined;
  // JSON round-trip first: Dates -> ISO strings, so projections see plain data.
  const clean = redact(JSON.parse(JSON.stringify(raw)));
  const projected = opts.output ? jmespath.search(clean, opts.output) : clean;
  const limit = opts.limit ?? 50;

  if (Array.isArray(projected)) {
    const items = projected.slice(0, limit);
    return {
      count: items.length,
      items,
      truncated: projected.length > limit || undefined,
      moreAvailable,
    };
  }
  if (projected && typeof projected === "object") return { ...(projected as object), moreAvailable };
  return { result: projected ?? null, moreAvailable };
}
