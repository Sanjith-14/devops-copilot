import type { DBInstance } from "@aws-sdk/client-rds";
import type { SecretListEntry } from "@aws-sdk/client-secrets-manager";
import { daysSince, type Finding, type Severity } from "../../core/helpers.js";

/** Pure security checks over AWS API responses — unit-tested in tests/security.test.ts. */

export const ACCESS_KEY_MAX_AGE_DAYS = 90;
export const SECRET_ROTATION_MAX_DAYS = 180;

export function rdsFindings(instances: DBInstance[]): Finding[] {
  return instances.flatMap((d) => {
    const resource = `rds:${d.DBInstanceIdentifier}`;
    const out: Finding[] = [];
    if (d.PubliclyAccessible) out.push({ severity: "high", resource, issue: "database is publicly accessible" });
    if (!d.StorageEncrypted) out.push({ severity: "medium", resource, issue: "storage is not encrypted" });
    if (!d.BackupRetentionPeriod) out.push({ severity: "medium", resource, issue: "automated backups disabled (0-day retention)" });
    if (!d.DeletionProtection) out.push({ severity: "low", resource, issue: "deletion protection is off" });
    return out;
  });
}

export function secretFindings(secrets: SecretListEntry[], now = Date.now()): Finding[] {
  return secrets.flatMap((s) => {
    const resource = `secret:${s.Name}`;
    if (!s.RotationEnabled) {
      const age = daysSince(s.LastChangedDate ?? s.CreatedDate, now);
      return [{ severity: "low" as Severity, resource, issue: `rotation disabled${age !== undefined ? ` (last changed ${age} days ago)` : ""}` }];
    }
    const sinceRotation = daysSince(s.LastRotatedDate, now);
    if (sinceRotation !== undefined && sinceRotation > SECRET_ROTATION_MAX_DAYS) {
      return [{ severity: "low" as Severity, resource, issue: `rotation enabled but last rotated ${sinceRotation} days ago` }];
    }
    return [];
  });
}

export interface IamUserFacts {
  userName: string;
  hasConsolePassword: boolean | "unknown";
  mfaDevices: number | "unknown";
  accessKeys: { id: string; status?: string; created?: Date | string }[] | "unknown";
  passwordLastUsed?: Date | string;
}

export function iamUserFindings(users: IamUserFacts[], now = Date.now()): Finding[] {
  return users.flatMap((u) => {
    const resource = `iam-user:${u.userName}`;
    const out: Finding[] = [];
    if (u.hasConsolePassword === true && u.mfaDevices === 0) {
      out.push({ severity: "high", resource, issue: "console access without MFA" });
    }
    if (Array.isArray(u.accessKeys)) {
      for (const k of u.accessKeys) {
        const age = daysSince(k.created, now);
        if (k.status === "Active" && age !== undefined && age > ACCESS_KEY_MAX_AGE_DAYS) {
          out.push({ severity: "medium", resource, issue: `active access key ${k.id.slice(0, 8)}… is ${age} days old (rotate every ${ACCESS_KEY_MAX_AGE_DAYS})` });
        }
      }
    }
    const idle = daysSince(u.passwordLastUsed, now);
    if (u.hasConsolePassword === true && idle !== undefined && idle > 180) {
      out.push({ severity: "low", resource, issue: `console password unused for ${idle} days — consider removing` });
    }
    return out;
  });
}

export function accountSummaryFindings(summary: Record<string, number> | undefined): Finding[] {
  if (!summary) return [];
  const out: Finding[] = [];
  if (summary.AccountMFAEnabled === 0) out.push({ severity: "high", resource: "root", issue: "root account has no MFA" });
  if (summary.AccountAccessKeysPresent) out.push({ severity: "high", resource: "root", issue: "root account has access keys" });
  return out;
}

export interface SectionResult {
  findings: Finding[];
  /** How many resources the section inspected. */
  total: number;
}

/**
 * Pass-rate score (like AWS Security Hub's "% of checks passed"): for each
 * checked section, the share of inspected resources with no high/medium
 * finding; the score is the mean across sections. Low findings are reported
 * but don't count. Any HIGH finding caps the grade at C.
 */
export function score(sections: SectionResult[]): { score: number; grade: string; method: string } {
  const rates = sections
    .filter((s) => s.total > 0)
    .map((s) => {
      const failing = new Set(s.findings.filter((f) => f.severity === "high" || f.severity === "medium").map((f) => f.resource));
      return Math.max(0, 1 - failing.size / s.total);
    });
  const value = rates.length ? Math.round((rates.reduce((a, b) => a + b, 0) / rates.length) * 100) : 100;
  let grade = value >= 90 ? "A" : value >= 75 ? "B" : value >= 60 ? "C" : value >= 40 ? "D" : "F";
  const hasHigh = sections.some((s) => s.findings.some((f) => f.severity === "high"));
  if (hasHigh && grade < "C") grade = "C";
  return {
    score: value,
    grade,
    method: "mean % of inspected resources per section with no high/medium finding; any high finding caps the grade at C",
  };
}
