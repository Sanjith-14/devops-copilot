import type { CopilotConfig, RiskLevel } from "./types.js";

export class GuardrailViolation extends Error {
  constructor(message: string) {
    super(message);
    this.name = "GuardrailViolation";
  }
}

export type Verdict = "allow" | "confirm" | "deny";

/**
 * Single policy point for the whole server, decided per call:
 *
 *  - read:        always allowed.
 *  - mutate:      the USER (not the LLM) must approve each call via MCP
 *                 elicitation when the client supports it. On clients without
 *                 elicitation, allowed only when DEVOPS_COPILOT_ALLOW_WRITE=true
 *                 was set explicitly in the server's env.
 *  - destructive: requires DEVOPS_COPILOT_ALLOW_DESTRUCTIVE=true AND a
 *                 per-call user confirmation. Never runs unconfirmed.
 *
 * The registry executes the verdict ("confirm" = send an elicitation request
 * to the client); this class stays pure and unit-testable.
 */
export class Guardrails {
  constructor(private cfg: CopilotConfig) {}

  decide(risk: RiskLevel, clientCanConfirm: boolean): { verdict: Verdict; reason?: string } {
    switch (risk) {
      case "read":
        return { verdict: "allow" };

      case "mutate":
        if (clientCanConfirm) return { verdict: "confirm" };
        if (this.cfg.allowWrite) return { verdict: "allow" };
        return {
          verdict: "deny",
          reason:
            "Blocked by guardrails: mutate tools need per-call user approval, but this MCP client does not " +
            "support elicitation. Set DEVOPS_COPILOT_ALLOW_WRITE=true in the server env to opt in without prompts.",
        };

      case "destructive":
        if (!this.cfg.allowDestructive) {
          return {
            verdict: "deny",
            reason:
              "Blocked by guardrails: destructive tools are disabled. Set DEVOPS_COPILOT_ALLOW_DESTRUCTIVE=true " +
              "in the server env (a per-call user confirmation is still required).",
          };
        }
        if (!clientCanConfirm) {
          return {
            verdict: "deny",
            reason:
              "Blocked by guardrails: destructive tools always require per-call user confirmation, but this " +
              "MCP client does not support elicitation.",
          };
        }
        return { verdict: "confirm" };
    }
  }
}
