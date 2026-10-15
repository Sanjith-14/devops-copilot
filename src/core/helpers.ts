/**
 * Small shared helpers for service modules: bounded concurrency, best-effort
 * sections (partial results instead of failing on one AccessDenied), timeouts,
 * and a common finding shape for audit-style tools.
 */

export type Severity = "high" | "medium" | "low" | "info";

export interface Finding {
  severity: Severity;
  resource: string;
  issue: string;
  [key: string]: unknown;
}

export const SEVERITY_RANK: Record<Severity, number> = { high: 0, medium: 1, low: 2, info: 3 };

export const bySeverity = <T extends { severity: Severity }>(a: T, b: T) =>
  SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity];

/** Run async work over items with bounded concurrency (be nice to API rate limits). */
export async function mapLimited<T, R>(items: T[], limit: number, fn: (item: T) => Promise<R>): Promise<R[]> {
  const out: R[] = [];
  for (let i = 0; i < items.length; i += limit) out.push(...(await Promise.all(items.slice(i, i + limit).map(fn))));
  return out;
}

export const isAccessDenied = (err: unknown) =>
  /AccessDenied|UnauthorizedOperation|not authorized|AuthorizationError/i.test(String(err));

/**
 * Run one section of a multi-part report. Failures (typically missing IAM
 * permissions) become a `skipped` note instead of failing the whole tool.
 */
export async function bestEffort<T>(
  fn: () => Promise<T>,
): Promise<{ status: "checked"; data: T } | { status: "skipped"; reason: string }> {
  try {
    return { status: "checked", data: await fn() };
  } catch (err) {
    const reason = isAccessDenied(err) ? `no permission (${firstLine(err)})` : firstLine(err);
    return { status: "skipped", reason };
  }
}

const firstLine = (err: unknown) => String(err).split("\n")[0].slice(0, 240);

export const daysSince = (d: Date | string | undefined, now = Date.now()) =>
  d ? Math.floor((now - new Date(d).getTime()) / 86_400_000) : undefined;

export class TimeoutError extends Error {}

/** Reject if `p` takes longer than `ms` (the underlying call is not aborted). */
export function withTimeout<T>(p: Promise<T>, ms: number, label: string): Promise<T> {
  let timer: NodeJS.Timeout;
  const timeout = new Promise<never>((_, reject) => {
    timer = setTimeout(
      () => reject(new TimeoutError(`${label} timed out after ${Math.round(ms / 1000)}s — narrow the request and retry.`)),
      ms,
    );
  });
  return Promise.race([p, timeout]).finally(() => clearTimeout(timer));
}
