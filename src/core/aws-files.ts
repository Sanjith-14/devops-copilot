import { readFileSync, writeFileSync, existsSync, mkdirSync, statSync } from "node:fs";
import { dirname, join } from "node:path";
import { homedir } from "node:os";
import { loadSharedConfigFiles } from "@smithy/shared-ini-file-loader";

/**
 * Reading/writing ~/.aws/config and ~/.aws/credentials, honoring the same
 * AWS_CONFIG_FILE / AWS_SHARED_CREDENTIALS_FILE overrides as the AWS CLI.
 */

export const awsPaths = (env: NodeJS.ProcessEnv = process.env) => ({
  config: env.AWS_CONFIG_FILE ?? join(homedir(), ".aws", "config"),
  credentials: env.AWS_SHARED_CREDENTIALS_FILE ?? join(homedir(), ".aws", "credentials"),
});

export type IniSection = Record<string, string | undefined>;
export interface AwsFiles {
  /** Keyed by profile name ("profile " prefix already stripped). */
  config: Record<string, IniSection>;
  credentials: Record<string, IniSection>;
}

export async function loadAwsFiles(): Promise<AwsFiles> {
  const { configFile, credentialsFile } = await loadSharedConfigFiles({ ignoreCache: true });
  return { config: configFile ?? {}, credentials: credentialsFile ?? {} };
}

/** Merged view of one profile across both files (config wins, like the CLI). */
export const profileSection = (files: AwsFiles, name: string): IniSection => ({
  ...(files.credentials[name] ?? {}),
  ...(files.config[name] ?? {}),
});

/** Change marker for hot-reload: both files' mtimes. */
export function awsFilesStamp(): string {
  const p = awsPaths();
  const m = (f: string) => (existsSync(f) ? statSync(f).mtimeMs : 0);
  return `${m(p.config)}:${m(p.credentials)}`;
}

const escapeRe = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

/** Replace (or append) one INI section in a file body. Pure, for tests. */
export function upsertIniSection(content: string, section: string, body: string): string {
  const block = `[${section}]\n${body.trim()}\n`;
  const pattern = new RegExp(`^\\[${escapeRe(section)}\\][^\\[]*`, "gm");
  if (pattern.test(content)) {
    pattern.lastIndex = 0;
    return content.replace(pattern, `${block}\n`).replace(/\n{3,}/g, "\n\n").replace(/\n+$/, "\n");
  }
  const sep = content.length === 0 || content.endsWith("\n\n") ? "" : content.endsWith("\n") ? "\n" : "\n\n";
  return content + sep + block;
}

/** Write one section (key = value lines, undefined values skipped) with 0600 perms. */
export function writeIniSection(file: string, section: string, entries: IniSection): void {
  mkdirSync(dirname(file), { recursive: true });
  const existing = existsSync(file) ? readFileSync(file, "utf-8") : "";
  const body = Object.entries(entries)
    .filter(([, v]) => v !== undefined && v !== "")
    .map(([k, v]) => `${k} = ${v}`)
    .join("\n");
  writeFileSync(file, upsertIniSection(existing, section, body), { mode: 0o600 });
}
