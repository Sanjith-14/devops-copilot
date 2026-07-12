import type { CopilotConfig } from "./types.js";

/**
 * Zero-config by design: there is no config file. AWS accounts are discovered
 * from the user's ~/.aws profiles (see aws-client.ts), and the few server
 * knobs come from environment variables — which MCP clients pass via the
 * "env" block of their server entry, so users never edit files in this repo.
 *
 *   DEVOPS_COPILOT_PROFILES         comma-separated allowlist of profiles to
 *                                   expose (default: all discovered)
 *   DEVOPS_COPILOT_DEFAULT_PROFILE  default account (falls back to
 *                                   AWS_PROFILE, then "default", then the
 *                                   first discovered profile)
 *   DEVOPS_COPILOT_SERVICES         comma-separated module list (default: all)
 *   DEVOPS_COPILOT_ALLOW_WRITE      "true" permits mutate tools on clients
 *                                   that cannot ask the user interactively
 *   DEVOPS_COPILOT_ALLOW_DESTRUCTIVE "true" + interactive confirmation
 *                                   required for destructive tools
 *   AWS_REGION                      fallback region (default us-east-1)
 */
export function loadConfig(env: NodeJS.ProcessEnv = process.env): CopilotConfig {
  const csv = (v?: string) =>
    v
      ?.split(",")
      .map((s) => s.trim())
      .filter(Boolean);

  const services = csv(env.DEVOPS_COPILOT_SERVICES);
  return {
    defaultRegion: env.AWS_REGION ?? env.AWS_DEFAULT_REGION ?? "us-east-1",
    defaultAccount: env.DEVOPS_COPILOT_DEFAULT_PROFILE ?? env.AWS_PROFILE,
    allowWrite: env.DEVOPS_COPILOT_ALLOW_WRITE === "true",
    allowDestructive: env.DEVOPS_COPILOT_ALLOW_DESTRUCTIVE === "true",
    profileAllowlist: csv(env.DEVOPS_COPILOT_PROFILES),
    enabledServices: services && services.length > 0 ? services : "*",
  };
}
