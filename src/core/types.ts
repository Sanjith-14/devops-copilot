import { z } from "zod";

/**
 * Risk tiers for guardrails.
 *  - read:        safe, always allowed
 *  - mutate:      changes state (scale ASG, restart instance) — requires allowWrite: true in config
 *  - destructive: deletes data (delete bucket, terminate instance) — blocked unless explicitly enabled
 */
export type RiskLevel = "read" | "mutate" | "destructive";

/** Context passed to every tool handler by the core. */
export interface ToolContext {
  /** Resolved account id (from the account registry in config.yaml). */
  accountId: string;
  /** Resolved AWS region for this call. */
  region: string;
}

/** Result shape every tool returns. The core tags it with account/region before sending to the LLM. */
export interface ToolResult {
  [key: string]: unknown;
}

/**
 * A single MCP tool exposed by a service module.
 * `inputSchema` is a zod raw shape; the core automatically injects optional
 * `account` and `region` parameters so modules never deal with account plumbing.
 */
export interface ToolDefinition {
  name: string;
  description: string;
  risk: RiskLevel;
  inputSchema: z.ZodRawShape;
  handler: (args: Record<string, unknown>, ctx: ToolContext) => Promise<ToolResult>;
}

/**
 * The plugin contract. Drop a folder in src/services/<name>/ with a default
 * export implementing this interface and the registry picks it up at startup.
 * Adding RDS/ElastiCache/EBS later = new folder, zero core changes.
 */
export interface ServiceModule {
  /** Short id, e.g. "s3", "asg", "rds". Used as tool name prefix. */
  name: string;
  description: string;
  tools: ToolDefinition[];
  /** Lightweight reachability probe, used by the health tool. */
  healthCheck(ctx: ToolContext): Promise<{ ok: boolean; detail?: string }>;
}

/**
 * What each services/<name>/index.ts default-exports: a function that
 * receives the shared AwsClientFactory and returns the module. Keeping this
 * as a factory (rather than a bare object) lets modules close over the
 * client factory without import cycles or globals.
 */
export type ServiceModuleFactory = (factory: import("./aws-client.js").AwsClientFactory) => ServiceModule;

/**
 * A usable AWS identity. Discovered automatically from ~/.aws profiles at
 * startup, or added at runtime by the assume_role core tool (ephemeral).
 */
export interface AccountConfig {
  /** Account id exposed to the LLM (profile name, or a label for assumed roles). */
  id: string;
  /** ~/.aws profile backing this account ("" for ephemeral assumed roles). */
  profile: string;
  description?: string;
  defaultRegion?: string;
}

/** Top-level server configuration — all sourced from environment variables. */
export interface CopilotConfig {
  defaultRegion: string;
  /** Preferred default account. Resolved against discovered profiles at startup. */
  defaultAccount?: string;
  /** Env fallback gate for "mutate" tools on clients without interactive confirmation. */
  allowWrite: boolean;
  /** Env gate for "destructive" tools (still requires interactive confirmation). */
  allowDestructive: boolean;
  /** Only expose these ~/.aws profiles. Undefined = all discovered. */
  profileAllowlist?: string[];
  /** Which service modules to load. "*" = all discovered. */
  enabledServices: string[] | "*";
}
