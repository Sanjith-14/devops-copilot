import { z } from "zod";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";

/**
 * MCP prompts: canned, user-selectable workflows (they appear in the client's
 * prompt / slash-command menu). Each is a recipe of tool calls; steps whose
 * tool isn't loaded (module disabled) are left out automatically.
 */

interface Step {
  tool: string;
  why: string;
}

interface Recipe {
  name: string;
  title: string;
  description: string;
  args: z.ZodRawShape;
  intro: (a: Record<string, string | undefined>) => string;
  steps: Step[];
  outro: string;
}

const scope = (a: Record<string, string | undefined>) =>
  a.account ? ` Use account "${a.account}" for every call.` : " Use the default account (list_accounts shows it).";

export const RECIPES: Recipe[] = [
  {
    name: "daily_health_report",
    title: "Daily health report",
    description: "Morning check: alarms, errors, spend spikes and security drift in one summary.",
    args: { account: z.string().optional().describe("Account id (default: the default account)") },
    intro: (a) => `Produce a concise daily health report for my AWS account.${scope(a)}`,
    steps: [
      { tool: "monitor_run_checks", why: "overall health checks with severity-tagged alerts" },
      { tool: "cloudwatch_list_alarms", why: "alarms currently in ALARM state" },
      { tool: "cost_detect_spend_spikes", why: "unusual spend" },
      { tool: "cloudtrail_recent_changes", why: "changes made in the last 24 hours (who/what)" },
      { tool: "security_scorecard", why: "security score and any new high findings" },
    ],
    outro:
      "Finish with: a one-line overall status (green/amber/red), then at most 5 bullet points ordered by urgency, each with the next action. Do not change anything.",
  },
  {
    name: "incident_triage",
    title: "Incident triage",
    description: "Something is broken: gather symptoms, recent changes and a likely cause.",
    args: {
      symptom: z.string().describe("What is wrong, e.g. 'api.example.com returns 502' or 'orders lambda failing'"),
      hours: z.string().optional().describe("How far back to look (default 2)"),
      account: z.string().optional().describe("Account id"),
    },
    intro: (a) =>
      `Help me triage an incident: "${a.symptom}". Look back ${a.hours ?? "2"} hours.${scope(a)} ` +
      "Pick only the steps relevant to the symptom.",
    steps: [
      { tool: "cloudwatch_list_alarms", why: "which alarms are firing" },
      { tool: "route53_trace_domain", why: "if a domain is involved: DNS -> load balancer -> targets and their health" },
      { tool: "elb_map_load_balancer", why: "unhealthy targets behind the load balancer" },
      { tool: "ecs_service_health", why: "if it runs on ECS: running vs desired tasks and why tasks stopped" },
      { tool: "lambda_function_errors", why: "if it is a Lambda: error rate and recent error logs" },
      { tool: "rds_get_db_metrics", why: "if a database is involved: CPU, connections, storage" },
      { tool: "cloudtrail_recent_changes", why: "what changed just before the incident — the most common root cause" },
    ],
    outro:
      "Then give: (1) timeline, (2) most likely cause with evidence, (3) what to check or do next. Recommend fixes but do NOT perform any changes.",
  },
  {
    name: "security_review",
    title: "Security review",
    description: "Prioritized security findings with remediation steps.",
    args: { account: z.string().optional().describe("Account id") },
    intro: (a) => `Run a security review of my AWS account.${scope(a)}`,
    steps: [
      { tool: "security_scorecard", why: "score and ranked findings across IAM, S3, network, RDS, secrets" },
      { tool: "ec2_find_open_security_groups", why: "details on internet-exposed ports" },
      { tool: "acm_expiring_certificates", why: "certificates about to expire" },
      { tool: "eks_describe_cluster", why: "if EKS clusters exist: public API endpoint exposure" },
      { tool: "tagging_find_untagged", why: "ownership gaps (who to contact per finding)" },
    ],
    outro:
      "Report findings grouped by severity. For each HIGH finding give the exact remediation (console path or CLI command) but do NOT run it.",
  },
  {
    name: "cost_review",
    title: "Cost review",
    description: "Where the money goes and what can be cleaned up.",
    args: { account: z.string().optional().describe("Account id") },
    intro: (a) => `Review my AWS costs.${scope(a)}`,
    steps: [
      { tool: "cost_daily_spend", why: "spend by service for the last 14 days" },
      { tool: "cost_detect_spend_spikes", why: "unusual days" },
      { tool: "cost_get_aws_anomalies", why: "AWS-detected cost anomalies" },
      { tool: "cost_find_waste", why: "unused resources still costing money" },
    ],
    outro: "Summarize the top cost drivers and list cleanup candidates with estimated monthly savings. Do not delete anything.",
  },
];

/** Build the prompt text from loaded tools only. Pure — unit-tested. */
export function renderRecipe(r: Recipe, args: Record<string, string | undefined>, loaded: Set<string>): string {
  const steps = r.steps.filter((s) => loaded.has(s.tool));
  const lines = steps.map((s, i) => `${i + 1}. \`${s.tool}\` — ${s.why}`);
  return [
    r.intro(args),
    "",
    lines.length ? "Use these tools (skip any that fail for lack of permission and say so):" : "No matching tools are loaded.",
    ...lines,
    "",
    r.outro,
  ].join("\n");
}

export function registerPrompts(server: McpServer, loadedTools: Set<string>): void {
  for (const r of RECIPES) {
    if (!r.steps.some((s) => loadedTools.has(s.tool))) continue;
    server.registerPrompt(r.name, { title: r.title, description: r.description, argsSchema: r.args }, (args) => ({
      messages: [
        {
          role: "user" as const,
          content: { type: "text" as const, text: renderRecipe(r, args as Record<string, string | undefined>, loadedTools) },
        },
      ],
    }));
  }
}
