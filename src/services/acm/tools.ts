import { ACMClient, type CertificateSummary } from "@aws-sdk/client-acm";
import { z } from "zod";
import type { ToolDefinition, ToolContext } from "../../core/types.js";
import type { AwsClientFactory } from "../../core/aws-client.js";
import { bySeverity, daysSince, type Finding } from "../../core/helpers.js";
import { allCertificates } from "../route53/tools.js";

/** Classify certificates by expiry risk. Pure — unit-tested. */
export function certificateFindings(certs: CertificateSummary[], withinDays: number, now = Date.now()): Finding[] {
  return certs.flatMap((c): Finding[] => {
    if (!c.NotAfter) return [];
    const daysLeft = -(daysSince(c.NotAfter, now) ?? 0);
    const resource = `acm:${c.DomainName}`;
    const base = { resource, daysLeft, expires: new Date(c.NotAfter).toISOString(), type: c.Type, inUse: c.InUse, arn: c.CertificateArn };
    if (daysLeft < 0) return [{ ...base, severity: c.InUse ? "high" : "low", issue: `EXPIRED ${-daysLeft} days ago${c.InUse ? " and still in use" : ""}` }];
    if (daysLeft > withinDays) return [];
    // ACM auto-renews AMAZON_ISSUED certs that are in use and DNS-validated; imported ones never renew.
    const autoRenews = c.Type === "AMAZON_ISSUED" && c.RenewalEligibility === "ELIGIBLE";
    const severity = autoRenews ? "info" : daysLeft <= 14 ? "high" : "medium";
    return [{ ...base, severity, issue: `expires in ${daysLeft} days${autoRenews ? " (eligible for automatic renewal)" : c.Type === "IMPORTED" ? " — IMPORTED, must be renewed manually" : " — not eligible for automatic renewal"}` }];
  });
}

export function buildAcmTools(factory: AwsClientFactory): ToolDefinition[] {
  const acm = (ctx: ToolContext) => factory.getClient(ACMClient, ctx.accountId, ctx.region).client;
  return [
    {
      name: "expiring_certificates",
      description:
        "Find TLS certificates in ACM that are expired or expire within N days (default 30). Flags imported " +
        "certificates (never auto-renewed) and ones not eligible for automatic renewal. CloudFront certificates " +
        "live in us-east-1 — pass region to check them.",
      risk: "read",
      inputSchema: {
        days: z.number().int().min(1).max(365).optional().describe("Expiry window in days (default 30)"),
      },
      handler: async (args, ctx) => {
        const certs = await allCertificates(acm(ctx));
        const findings = certificateFindings(certs, (args.days as number | undefined) ?? 30).sort(bySeverity);
        return { certificatesScanned: certs.length, count: findings.length, findings };
      },
    },
  ];
}
